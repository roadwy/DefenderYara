
rule Trojan_Win32_Cridex_MBFW_MTB{
	meta:
		description = "Trojan:Win32/Cridex.MBFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {77 72 74 79 77 68 71 61 65 20 76 20 61 77 72 74 77 71 68 72 20 72 73 67 74 66 00 73 64 66 62 67 61 64 } //1
		$a_01_1 = {52 00 54 00 55 00 54 00 49 00 4c 00 53 00 2e 00 44 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}