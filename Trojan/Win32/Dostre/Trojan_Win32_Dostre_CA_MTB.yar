
rule Trojan_Win32_Dostre_CA_MTB{
	meta:
		description = "Trojan:Win32/Dostre.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c1 33 d2 f7 f3 8a 04 2a 8a 14 31 32 d0 88 14 31 41 3b cf 72 ea } //1
		$a_01_1 = {25 73 2e 65 78 65 } //1 %s.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}