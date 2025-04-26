
rule Backdoor_Win32_Dridex_SF_MTB{
	meta:
		description = "Backdoor:Win32/Dridex.SF!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4e 38 8a 46 5c 30 04 11 42 3b 56 3c 72 f1 83 7e 44 00 } //1
		$a_01_1 = {8b 4e 40 8a 46 5c 30 04 11 42 3b 56 44 72 f1 8b 7e 18 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}