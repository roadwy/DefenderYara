
rule Trojan_Win32_Banload_MBFW_MTB{
	meta:
		description = "Trojan:Win32/Banload.MBFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 72 71 75 69 76 6f 00 44 53 43 32 30 34 30 31 30 00 00 44 53 43 32 30 34 30 31 30 } //1
		$a_01_1 = {4c 15 40 00 4c 15 40 00 08 15 40 00 78 00 00 00 80 00 00 00 8a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}