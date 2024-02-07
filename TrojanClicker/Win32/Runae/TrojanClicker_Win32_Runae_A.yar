
rule TrojanClicker_Win32_Runae_A{
	meta:
		description = "TrojanClicker:Win32/Runae.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 41 49 4e 00 00 00 00 56 65 72 73 69 6f 6e 00 41 75 74 6f 49 45 2e 69 6e 69 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 70 72 6f 63 65 73 73 0a } //01 00  牃慥整牰捯獥ੳ
		$a_00_2 = {25 73 63 6c 69 63 6b 5f 6c 6f 67 2e 61 73 70 3f 61 64 5f 75 72 6c 3d 25 73 } //01 00  %sclick_log.asp?ad_url=%s
		$a_00_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6e 69 75 64 6f 75 64 6f 75 2e 63 6f 6d } //00 00  http://www.niudoudou.com
	condition:
		any of ($a_*)
 
}