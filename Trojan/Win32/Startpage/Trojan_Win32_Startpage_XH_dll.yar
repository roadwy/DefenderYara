
rule Trojan_Win32_Startpage_XH_dll{
	meta:
		description = "Trojan:Win32/Startpage.XH!dll,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 64 68 30 30 35 2e 63 6f 6d 2f 3f } //01 00 
		$a_01_1 = {32 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 49 00 } //01 00 
		$a_03_2 = {39 37 37 64 68 2e 63 6f 6d 90 01 03 35 39 38 2e 6e 65 74 90 01 01 32 31 31 64 68 2e 63 6f 6d 90 01 03 39 33 36 35 2e 69 6e 66 6f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}