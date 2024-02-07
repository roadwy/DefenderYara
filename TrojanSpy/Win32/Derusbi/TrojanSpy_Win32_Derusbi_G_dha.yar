
rule TrojanSpy_Win32_Derusbi_G_dha{
	meta:
		description = "TrojanSpy:Win32/Derusbi.G!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 73 6f 6c 75 74 69 6f 6e 73 2f 63 6f 6d 70 61 6e 79 2d 73 69 7a 65 2f 73 6d 62 2f 69 6e 64 65 78 2e 68 74 6d } //01 00  /solutions/company-size/smb/index.htm
		$a_01_1 = {2f 73 65 6c 66 73 65 72 76 69 63 65 2f 6d 69 63 72 6f 73 69 74 65 73 2f 73 65 61 72 63 68 2e 70 68 70 } //01 00  /selfservice/microsites/search.php
		$a_01_2 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 22 2c 4e 6c 61 4e 6f 74 45 71 75 61 6c } //01 00  rundll32.exe "%s",NlaNotEqual
		$a_00_3 = {45 00 31 00 39 00 30 00 42 00 43 00 37 00 39 00 2d 00 30 00 32 00 44 00 43 00 2d 00 30 00 31 00 36 00 36 00 2d 00 34 00 43 00 46 00 31 00 2d 00 42 00 44 00 38 00 46 00 38 00 43 00 42 00 32 00 46 00 46 00 32 00 31 00 } //00 00  E190BC79-02DC-0166-4CF1-BD8F8CB2FF21
	condition:
		any of ($a_*)
 
}