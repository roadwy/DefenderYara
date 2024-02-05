
rule Trojan_Win32_GhostRAT_MB_MTB{
	meta:
		description = "Trojan:Win32/GhostRAT.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {46 75 63 6b 42 61 62 79 2e 64 6c 6c } //02 00 
		$a_01_1 = {77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //01 00 
		$a_01_2 = {8d 4c 24 48 8d 54 24 10 51 68 3f 00 0f 00 6a 00 52 68 02 00 00 80 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}