
rule Trojan_Win32_Mutelat_B{
	meta:
		description = "Trojan:Win32/Mutelat.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 4d 75 74 65 49 6e 73 74 61 6c 6c 5c 52 65 6c 65 61 73 65 5c 4d 75 74 65 49 6e 73 74 61 6c 6c 2e 70 64 62 } //01 00  \MuteInstall\Release\MuteInstall.pdb
		$a_01_1 = {6d 75 74 65 69 6e 73 74 61 6c 6c 00 } //01 00  畭整湩瑳污l
		$a_01_2 = {6f 66 66 65 72 5f 69 64 3d 28 5c 77 2b 29 26 61 66 66 5f 69 64 3d 28 5c 77 2b 29 26 74 72 61 6e 73 61 63 74 69 6f 6e 5f 69 64 3d 28 5b 5c 77 2d 5d 2b 29 24 } //01 00  offer_id=(\w+)&aff_id=(\w+)&transaction_id=([\w-]+)$
		$a_01_3 = {4a 61 76 61 20 49 6e 73 74 61 6c 6c 65 72 20 69 6e 73 74 61 6c 6c 20 70 72 6f 67 72 65 73 73 00 } //01 00  慊慶䤠獮慴汬牥椠獮慴汬瀠潲牧獥s
		$a_01_4 = {49 6e 73 74 61 6c 6c 20 59 6f 75 72 20 53 6f 66 74 77 61 72 65 00 00 00 23 33 32 37 37 30 00 } //00 00 
		$a_00_5 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}