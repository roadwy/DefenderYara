
rule Backdoor_MacOS_Empyre_F_MTB{
	meta:
		description = "Backdoor:MacOS/Empyre.F!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5f 61 63 74 69 76 61 74 65 53 74 61 67 65 72 } //1 _activateStager
		$a_00_1 = {5f 69 6e 69 74 69 61 6c 69 7a 65 72 } //1 _initializer
		$a_00_2 = {5f 50 79 5f 49 6e 69 74 69 61 6c 69 7a 65 } //1 _Py_Initialize
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}