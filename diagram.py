#!/usr/bin/env python

# sudo python diagram.py -o example.png -t graphviz_tn -u https://10.61.6.121:20109/ -l automation -p automation123

from acitoolkit.acitoolkit import *
import pygraphviz as pgv
import sys


creds = Credentials('apic', "Generate logical diagrams of a running Cisco ACI")

# Defining command line arguments
creds.add_argument('-o', '--output', help='Output file for diagram, e.g. out.png, out.jpeg', required=True)
creds.add_argument('-t', '--tenants', help='Tenants to include when generating diagrams', nargs='*')
creds.add_argument('-v', '--verbose', help='Verbose logging information', action='store_true')

# Getting gredentials from a user
args = creds.get()

session = Session(args.url, args.login, args.password)

try:
    assert(session.login().ok)
except:
    print "Connection to APIC failed!"
    sys.exit()

graph=pgv.AGraph(directed=True, rankdir="LR")

if args.tenants:
    tenants=Tenant.get_deep(session, args.tenants)
else:
    tenants=Tenant.get_deep(session)

# Defining nodes for graphviz
def tn_node(tn):
    return "cluster-tn-"+tn.name

def ctx_node(tn,ctx):
    return tn_node(tn)+"/ctx-"+ctx.name

def bd_node(tn, bd):
    return tn_node(tn)+"/bd-"+bd.name

def sn_node(tn, bd, sn):
    return bd_node(tn, bd)+"/sn-"+sn.get_addr()

def app_node(tn, app):
    return tn_node(tn)+"/app-"+app.name

def epg_node(tn, app, epg):
    return app_node(tn, app)+"/epg-"+epg.name

def ctrct_node(tn, ctrct):
    return tn_node(tn)+"/ctrct-"+ctrct.name

def l3out_node(tn, l3out):
    return tn_node(tn)+"/l3out-"+l3out.name

def outside_epg_node(tn, l3out, exEpg):
    return l3out_node(tn, l3out)+"/outside-epg-"+exEpg.name

for tenant in tenants:
    print "Processing tenant "+tenant.name

    # Plot Tenant
    tnCluster = graph.add_subgraph(name=tn_node(tenant), label="Tenant\n"+tenant.name, color="blue")

    # Plot VRFs
    for context in tenant.get_children(only_class=Context):
        tnCluster.add_node(ctx_node(tenant, context), label="VRF\n"+context.name, shape='box')

    # Plot L3Out in a separate subgraph
    for l3out in tenant.get_children(only_class=OutsideL3):
        l3outCluster=tnCluster.add_subgraph(name=l3out_node(tenant,l3out), label="L3Out")
        l3outCluster.add_node(l3out_node(tenant, l3out), label = "L3Out\n"+l3out.name, shape='box')

        # Plot connection to VRF
        if l3out.get_context():
            tnCluster.add_edge(ctx_node(tenant,l3out.get_context()), l3out_node(tenant,l3out), style='dotted')

        # Plot External EPGs
        for exEpg in l3out.get_children(only_class=OutsideEPG):

            # Create External EPGs label that lists all Networks
            exEpglabel="Outside EPG\n"+exEpg.name
            for ntw in exEpg.get_children(only_class=OutsideNetwork):
                exEpglabel=exEpglabel+"\n"+ntw.get_addr()

            l3outCluster.add_node(outside_epg_node(tenant, l3out, exEpg), label = exEpglabel)
            l3outCluster.add_edge(l3out_node(tenant, l3out), outside_epg_node(tenant, l3out, exEpg))

            # If External EPGs is providing a Contract - plot a Contract and a connection
            for pc in exEpg.get_all_provided():

                # Create Contract label that lists all Subjects
                cLabel="Contract\n"+pc.name
                for sj in pc.get_children(only_class=ContractSubject):
                    cLabel=cLabel+"\nSubject: "+sj.name

                l3outCluster.add_node(ctrct_node(tenant, pc), label=cLabel, shape='box', style='filled', color='lightgray')
                l3outCluster.add_edge(outside_epg_node(tenant, l3out, exEpg), ctrct_node(tenant, pc))

            # If External EPGs is consuming a Contract - plot a Contract and a connection
            for cc in exEpg.get_all_consumed():

                # Create Contract label that lists all Subjects
                cLabel="Contract\n"+cc.name
                for sj in cc.get_children(only_class=ContractSubject):
                    cLabel=cLabel+"\nSubject: "+sj.name

                l3outCluster.add_node(ctrct_node(tenant, cc), label=cLabel, shape='box', style='filled', color='lightgray')
                l3outCluster.add_edge(ctrct_node(tenant, cc), outside_epg_node(tenant, l3out, exEpg))

    # Plot BDs
    for bd in tenant.get_children(only_class=BridgeDomain):

        # Create BD label that lists all attached Subnets
        bdLabel="Bridge Domain\n"+bd.name

        for sn in bd.get_children(only_class=Subnet):
            bdLabel=bdLabel+"\n"+sn.get_addr()

        # Plot BD
        tnCluster.add_node(bd_node(tenant, bd), label=bdLabel, shape='box')

        # If BD is attached to VRF
        if bd.get_context():
            tnCluster.add_edge(ctx_node(tenant,bd.get_context()), bd_node(tenant,bd))
        else:
            tnCluster.add_node("_ctx-dummy-"+bd_node(tenant, bd), style="invis", label='Private Network', shape='circle')
            tnCluster.add_edge("_ctx-dummy-"+bd_node(tenant, bd), bd_node(tenant, bd), style="invis")

        # If BD has L3Out then plot connection
        for l3out in bd.get_l3out():
            tnCluster.add_edge(bd_node(tenant, bd), l3out_node(tenant, l3out), style='dotted')

    # Plot Application Profile
    for app in tenant.get_children(only_class=AppProfile):
        appCluster=tnCluster.add_subgraph(name=app_node(tenant, app), label="Application Profile\n"+app.name)

        # Plot EPGs
        for epg in app.get_children(only_class=EPG):
            appCluster.add_node(epg_node(tenant, app, epg), label="EPG\n"+epg.name)

            # If EPG is attached to BD - plot a connection
            if epg.has_bd():
                tnCluster.add_edge(bd_node(tenant,epg.get_bd()), epg_node(tenant, app, epg), style='dotted')

            # If EPG is providing a Contract - plot a Contract and a connection
            for pc in epg.get_all_provided():

                # Create Contract label that lists all Subjects
                cLabel="Contract\n"+pc.name
                for sj in pc.get_children(only_class=ContractSubject):
                    cLabel=cLabel+"\nSubject: "+sj.name

                appCluster.add_node(ctrct_node(tenant, pc), label=cLabel, shape='box', style='filled', color='lightgray')
                appCluster.add_edge(epg_node(tenant, app, epg), ctrct_node(tenant, pc))

            # If EPG is consuming a Contract - plot a Contract and a connection
            for cc in epg.get_all_consumed():

                # Create Contract label that lists all Subjects
                cLabel="Contract\n"+cc.name
                for sj in cc.get_children(only_class=ContractSubject):
                    cLabel=cLabel+"\nSubject: "+sj.name

                appCluster.add_node(ctrct_node(tenant, cc), label=cLabel, shape='box', style='filled', color='lightgray')
                appCluster.add_edge(ctrct_node(tenant, cc), epg_node(tenant, app, epg))

if args.verbose:
    print "Finished loading the structure from APIC, here is the graph source (GraphViz DOT format):"
    print "================================================================================"
    print graph.string()
    print "================================================================================"

print "\n\nDrawing graph to %s"%args.output
graph.draw(args.output, prog='dot')
