
rule Trojan_Win32_Offloader_CCBO_MTB{
	meta:
		description = "Trojan:Win32/Offloader.CCBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6c 00 69 00 70 00 73 00 70 00 61 00 72 00 6b 00 2e 00 73 00 69 00 74 00 65 00 2f 00 68 00 75 00 72 00 2e 00 70 00 68 00 70 00 3f } //1
		$a_01_1 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}