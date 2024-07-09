
rule Trojan_Win32_Meteit_D{
	meta:
		description = "Trojan:Win32/Meteit.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 03 01 00 00 50 8b 45 ?? 53 03 c7 33 f6 ff d0 48 78 24 8a 8c 05 ?? ?? ff ff 8d 94 05 ?? ?? ff ff 80 f9 5c 74 11 80 f9 41 7c e5 80 f9 5a 7f e0 80 c1 20 88 0a eb d9 } //1
		$a_03_1 = {c7 45 fc bb bb 00 00 81 7d fc aa aa 00 00 72 04 83 65 fc 00 8b 45 ?? 8b 4d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}