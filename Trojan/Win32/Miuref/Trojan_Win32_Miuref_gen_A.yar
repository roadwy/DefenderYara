
rule Trojan_Win32_Miuref_gen_A{
	meta:
		description = "Trojan:Win32/Miuref.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 46 54 03 41 3c 57 e8 ?? ?? ?? ?? 8b 4d 08 8b 41 3c 03 c7 } //1
		$a_03_1 = {8b 06 8b 48 28 85 c9 74 ?? 8b 46 04 03 c1 74 ?? 6a ff 6a 01 6a 00 ff d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}