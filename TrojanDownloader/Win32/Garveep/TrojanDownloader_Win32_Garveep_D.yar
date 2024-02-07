
rule TrojanDownloader_Win32_Garveep_D{
	meta:
		description = "TrojanDownloader:Win32/Garveep.D,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 62 69 6e 2f 72 65 61 64 5f 69 2e 70 68 70 } //01 00  /bin/read_i.php
		$a_01_1 = {2f 62 69 6e 2f 68 6f 6d 65 2f 68 6f 6d 65 2e 70 68 70 } //01 00  /bin/home/home.php
		$a_01_2 = {66 61 69 6c 20 74 6f 20 67 65 74 } //01 00  fail to get
		$a_01_3 = {25 73 3f 61 31 3d 25 73 26 61 32 3d 25 73 26 61 33 3d 25 73 26 61 34 3d 4e 4f 54 55 53 45 44 } //00 00  %s?a1=%s&a2=%s&a3=%s&a4=NOTUSED
	condition:
		any of ($a_*)
 
}