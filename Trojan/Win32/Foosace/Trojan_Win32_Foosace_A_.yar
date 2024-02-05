
rule Trojan_Win32_Foosace_A_{
	meta:
		description = "Trojan:Win32/Foosace.A!!Foosace.gen!dha,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_80_0 = {58 53 51 57 45 52 53 79 73 74 65 6d 43 72 69 74 69 63 61 6c } //XSQWERSystemCritical  01 00 
		$a_80_1 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c 63 68 65 63 6b 5f 6d 65 73 5f 76 35 35 35 35 } //\\.\mailslot\check_mes_v5555  01 00 
		$a_80_2 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c 39 64 64 39 64 33 65 63 2d 31 63 30 66 2d 34 36 32 36 2d 61 36 37 35 2d 39 30 32 39 62 62 38 65 36 30 33 } //\\.\mailslot\9dd9d3ec-1c0f-4626-a675-9029bb8e603  0a 00 
	condition:
		any of ($a_*)
 
}