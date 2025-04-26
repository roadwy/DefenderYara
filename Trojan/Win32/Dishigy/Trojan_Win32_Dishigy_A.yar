
rule Trojan_Win32_Dishigy_A{
	meta:
		description = "Trojan:Win32/Dishigy.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 b8 24 00 e8 ?? ?? ?? ?? 8b 55 ec } //1
		$a_03_1 = {b8 e7 03 00 00 e8 ?? ?? ?? ?? 8d 55 d8 } //1
		$a_03_2 = {c7 80 c8 01 00 00 db 05 00 00 8b 45 f8 83 c0 34 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? b8 75 00 00 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}