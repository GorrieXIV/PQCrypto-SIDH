'''
this script is used to run the TestPsiS.mag magma script
first, sig_test.c is run and the output is funnelled into psi_test_values
then the values are serially fed into TestPsiS.mag at the right locations
then TestPsiS is run, checking the validity of PsiS

From sig_test.c we need:
- the A value of every iteration
- psi(S) of every iteration
- R1 of every iteration
- R2 of every iteration
- a of every iteration
- b of every iteration
- bit of every iteration
'''
