
rule Trojan_Win32_Rebrela_A{
	meta:
		description = "Trojan:Win32/Rebrela.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {75 69 64 3d 25 73 26 69 70 3d 25 73 26 75 73 65 72 6e 61 6d 65 3d 25 73 } //1 uid=%s&ip=%s&username=%s
		$a_03_1 = {ff 56 04 8b d8 55 6a 08 53 ff 56 08 8d 96 90 01 02 00 00 8b f8 52 6a 00 6a 06 ff 56 0c 6a 00 6a 00 6a 00 6a 06 50 ff 56 10 8b 8e 90 01 02 00 00 8d 96 90 01 02 00 00 52 03 c8 6a 00 6a 06 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}