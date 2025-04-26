
rule Trojan_Win32_Reline_FSB_MTB{
	meta:
		description = "Trojan:Win32/Reline.FSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 61 30 35 35 31 30 30 32 2e 78 73 70 68 2e 72 75 } //1 http://a0551002.xsph.ru
		$a_00_1 = {43 3a 5c 55 73 65 72 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 44 65 73 6b 74 6f 70 5c 63 72 79 70 74 6f 72 5c 6c 6f 61 64 65 72 20 72 75 6e 70 65 } //1 C:\Users\Administrator\Desktop\cryptor\loader runpe
	condition:
		((#a_81_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}