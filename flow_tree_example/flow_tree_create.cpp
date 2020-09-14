#include <libflowtree/flow_tree.h>
#include <libflowtree/flow_tree_io.hpp>
#include <iostream>
int main(void){
  using namespace std;
  ft_config_t *ft = NULL;
  cout << "creating flow_tree " << endl; 
  ft = create_ft_config();
  cout << "destroying flow_tree " << endl; 
  free_ft_config(ft);
  cout << "flowtree was successfully built" << endl;
  return 0; 
}
