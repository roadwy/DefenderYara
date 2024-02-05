
rule Trojan_WinNT_Waltrodock_B{
	meta:
		description = "Trojan:WinNT/Waltrodock.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 62 52 65 66 65 72 65 6e 63 65 4f 62 6a 65 63 74 42 79 48 61 6e 64 6c 65 } //01 00 
		$a_01_1 = {75 1a 8b 4d 0c be 34 00 00 c0 32 d2 89 71 18 89 79 1c ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}