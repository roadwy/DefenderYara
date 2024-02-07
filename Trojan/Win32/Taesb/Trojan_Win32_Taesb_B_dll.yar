
rule Trojan_Win32_Taesb_B_dll{
	meta:
		description = "Trojan:Win32/Taesb.B!dll,SIGNATURE_TYPE_PEHSTR,10 00 0f 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {2a 00 5c 00 41 00 43 00 3a 00 5c 00 79 00 30 00 5a 00 61 00 38 00 5c 00 77 00 70 00 61 00 64 00 5c 00 77 00 70 00 61 00 64 00 2e 00 76 00 62 00 70 00 } //05 00  *\AC:\y0Za8\wpad\wpad.vbp
		$a_01_1 = {77 70 61 64 2e 64 6c 6c } //01 00  wpad.dll
		$a_01_2 = {5a 68 10 de 02 11 68 14 de 02 11 52 e9 } //00 00 
	condition:
		any of ($a_*)
 
}