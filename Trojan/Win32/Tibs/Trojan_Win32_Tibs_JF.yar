
rule Trojan_Win32_Tibs_JF{
	meta:
		description = "Trojan:Win32/Tibs.JF,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 0f 6e da 66 0f 7e d9 90 09 0a 00 ff 55 e4 c9 c3 ba } //1
		$a_03_1 = {66 0f 6e c8 0f 54 c1 66 0f 7e c2 8a 02 34 ?? 3c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}