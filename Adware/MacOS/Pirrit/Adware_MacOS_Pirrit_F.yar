
rule Adware_MacOS_Pirrit_F{
	meta:
		description = "Adware:MacOS/Pirrit.F,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2d 52 4f 46 6b 4d 43 4d 31 } //1 -ROFkMCM1
		$a_01_1 = {6d 4b 32 4c 32 4e 39 } //1 mK2L2N9
		$a_01_2 = {43 2a 6c 30 73 2b 3d } //1 C*l0s+=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}