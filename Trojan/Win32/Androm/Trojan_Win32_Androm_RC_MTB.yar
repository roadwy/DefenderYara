
rule Trojan_Win32_Androm_RC_MTB{
	meta:
		description = "Trojan:Win32/Androm.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 54 24 08 52 6a 40 68 78 da 04 00 56 ff d0 6a 00 6a 00 56 56 6a 00 6a 00 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Androm_RC_MTB_2{
	meta:
		description = "Trojan:Win32/Androm.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c1 ce 0d 3c 61 0f be c0 7c 03 83 e8 20 03 f0 41 8a 01 84 c0 75 ea } //1
		$a_01_1 = {33 d2 8b c6 f7 f3 8a 0c 2a 30 0c 3e 46 3b 74 24 18 72 ed } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}