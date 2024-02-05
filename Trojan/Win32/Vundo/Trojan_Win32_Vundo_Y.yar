
rule Trojan_Win32_Vundo_Y{
	meta:
		description = "Trojan:Win32/Vundo.Y,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 93 30 86 20 c3 d9 38 dc 13 87 2f 99 52 6f d0 c5 ae 6f 38 3f bd d9 38 d4 45 8b 48 20 8c 57 74 } //00 00 
	condition:
		any of ($a_*)
 
}