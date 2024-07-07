
rule Trojan_Win32_Cromptui_A{
	meta:
		description = "Trojan:Win32/Cromptui.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d b7 00 00 00 0f 84 4f 0d 00 00 68 a9 1e 00 00 } //1
		$a_01_1 = {c6 45 02 32 c6 45 03 31 eb 10 c6 45 00 31 c6 45 01 32 } //1
		$a_01_2 = {6a 50 50 55 ff 54 24 70 6a 00 8b c8 6a 00 6a 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}