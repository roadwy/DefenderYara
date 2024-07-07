
rule Trojan_Win32_Meteit_F{
	meta:
		description = "Trojan:Win32/Meteit.F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 03 01 00 00 50 8b 45 90 01 01 53 03 c7 33 f6 ff d0 48 78 24 8a 8c 05 90 01 02 ff ff 8d 94 05 90 01 02 ff ff 80 f9 5c 74 11 80 f9 41 7c e5 80 f9 5a 7f e0 80 c1 20 88 0a eb d9 90 00 } //1
		$a_01_1 = {8b 7d 0c 81 e1 ff 0f 00 00 03 cb 01 39 8b 48 04 ff 45 08 83 e9 08 42 d1 e9 42 39 4d 08 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}