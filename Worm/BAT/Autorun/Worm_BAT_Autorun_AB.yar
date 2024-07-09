
rule Worm_BAT_Autorun_AB{
	meta:
		description = "Worm:BAT/Autorun.AB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_02_0 = {43 6f 70 79 20 2f 59 20 25 [0-50] 5c 73 79 73 74 65 6d 33 32 5c [0-30] 2e 65 78 65 } //1
		$a_00_1 = {66 6f 72 20 25 25 69 20 69 6e 20 28 43 2c 44 2c 45 2c 46 2c 47 2c 48 2c 49 2c 4a 2c 4b 2c 4c 2c 4d 2c 4e 2c 4f 2c 50 2c 51 2c 52 2c 53 2c 54 2c 55 2c 56 2c 57 2c 58 2c 59 2c 59 2c 5a 29 } //1 for %%i in (C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Y,Z)
		$a_00_2 = {44 65 6c 20 2f 46 20 2f 51 20 2f 41 20 25 44 69 73 6b 25 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 Del /F /Q /A %Disk%\autorun.inf
		$a_02_3 = {43 6f 70 79 20 2f 59 20 25 6e 61 6d 25 [0-30] 5b 25 52 41 4e 44 4f 4d 25 5d [0-30] 2d 50 69 63 74 75 72 65 2e 65 78 65 } //1
		$a_00_4 = {61 74 74 72 69 62 20 2b 72 20 2b 73 20 2b 68 20 25 6e 61 6d 25 } //1 attrib +r +s +h %nam%
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}