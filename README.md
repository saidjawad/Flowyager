# FlowYager Demo
## 1. Download the VM image
You can download FlowYager VM image [here](https://inet-flowyager.mpi-inf.mpg.de/data/FlowStream-TNSM.ova). 
## 2. Run Flowyager Demo
1. Import the VM on a hypervisor, e.g. VirtualBox, and start the VM.
2. Enter with username=root and password=123. 
3. On Desktop, you will find the FlowYager directory. Here are all the necessary files to run the demo. 
4. First start FlowYager. Open a Terminal and enter:
```
# cd /root/Desktop/FlowYager
# ./fs_site fs_site.config
```
4. Then run the demo. Open a second terminal window and enter:
```
# cd /root/Desktop/FlowYager/shiny/flowtree-4.0/src
# Rscript app.R
```
5. When you see "Listening on http://0.0.0.0:3737" on the second Terminal, the Demo is runnig and you can open the browser and enter 0.0.0.0:3737. You should be able to see the Demo page. 
6. Choose the plot you wish to see from the checkbox in the sidebar.
7. Now press the Update Plot button and wait for the plot to be created. It might take 1-2 mins.
8. Play with the values in the sidebar to see how that changes the plot. The following is the explanation of each sidebar field and in which plot you need them:
   - Time range: The time interval in which you want to see the results. The maximum and minimum possible amount is chosen by default. This will be used in all the plots.
   - Direction: Direction of the traffic. In other words, this will be the site ID for your queries. This will be used in all the plots.
   - Size of each bin(min): The granularity of the trees that are going to be fetched from FlowDB. This will be used in DDoS plot and Application Trends.
   - DDoS port: The port number you want to inspect. This will be used in the DDoS plot. 
   - Tree mode: The feature-set of the trees that are going to be fetched from FlowDB. For the demo, we only support SP or DP. This will be used in all the plots except the heatmap. For heatmap, the feature-set is SPDP.
   - Port range: The port range to be shown in the Ports Estimated Popularity plot.
   - Aggregation level: Aggregation level to be used in the Port Heatmap plot.
