
rule TrojanDownloader_Win32_Ksare_A{
	meta:
		description = "TrojanDownloader:Win32/Ksare.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 65 6c 65 74 65 20 48 4b 4c 4d 5c 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 53 61 66 65 42 6f 6f 74 5c 4d 69 6e 69 6d 61 6c 5c 7b 34 44 33 36 45 39 36 37 2d 45 33 32 35 2d 31 31 43 45 2d 42 46 43 31 2d 30 38 30 30 32 42 45 31 30 33 31 38 7d 20 2f 46 } //01 00  delete HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\{4D36E967-E325-11CE-BFC1-08002BE10318} /F
		$a_00_1 = {5a 77 4f 70 65 6e 53 65 63 74 69 6f 6e } //01 00  ZwOpenSection
		$a_00_2 = {25 48 25 4d 25 53 } //01 00  %H%M%S
		$a_03_3 = {50 56 8d 85 90 01 04 50 68 e8 03 00 00 ff 35 90 01 04 89 90 01 05 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}