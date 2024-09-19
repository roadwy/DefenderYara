
rule Trojan_Win32_Amadey_PAEP_MTB{
	meta:
		description = "Trojan:Win32/Amadey.PAEP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 4d fc 30 08 46 3b 75 0c 7c e2 } //1
		$a_03_1 = {69 c0 fd 43 03 00 05 c3 9e 26 00 81 3d ?? ?? ?? ?? 81 13 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}