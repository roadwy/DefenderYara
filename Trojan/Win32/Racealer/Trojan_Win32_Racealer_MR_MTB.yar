
rule Trojan_Win32_Racealer_MR_MTB{
	meta:
		description = "Trojan:Win32/Racealer.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 0c 00 00 05 00 "
		
	strings :
		$a_81_0 = {2f 64 6c 63 2f 64 69 73 74 72 69 62 75 74 69 6f 6e 2e 70 68 70 } //05 00  /dlc/distribution.php
		$a_81_1 = {2f 73 74 61 74 73 2f 73 74 61 74 69 73 74 69 63 73 2e 70 68 70 } //05 00  /stats/statistics.php
		$a_81_2 = {2f 73 74 61 74 73 2f 72 65 6d 65 6d 62 65 72 2e 70 68 70 } //05 00  /stats/remember.php
		$a_81_3 = {2f 73 74 61 74 73 2f 66 69 72 73 74 2e 70 68 70 } //05 00  /stats/first.php
		$a_81_4 = {2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 } //05 00  /download.php
		$a_81_5 = {5c 61 6c 72 65 61 64 79 64 6f 6e 65 2e 74 78 74 } //01 00  \alreadydone.txt
		$a_81_6 = {2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d } //01 00  /c taskkill /im
		$a_81_7 = {2f 66 20 26 20 65 72 61 73 65 } //01 00  /f & erase
		$a_81_8 = {4b 49 4c 4c 4d 45 } //01 00  KILLME
		$a_81_9 = {26 20 65 78 69 74 } //01 00  & exit
		$a_81_10 = {53 4f 46 54 4f 4c 44 } //01 00  SOFTOLD
		$a_81_11 = {45 6c 65 76 61 74 65 64 } //00 00  Elevated
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Racealer_MR_MTB_2{
	meta:
		description = "Trojan:Win32/Racealer.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 02 00 "
		
	strings :
		$a_02_0 = {0f b6 c2 03 05 90 01 04 89 0d 90 01 04 25 90 01 04 8a 98 90 01 04 88 90 01 05 a3 90 01 04 88 99 90 01 04 0f b6 80 90 01 04 0f b6 cb 03 c1 25 90 01 04 0f b6 90 01 05 30 14 3e b8 90 01 04 29 44 24 90 01 01 8b 74 24 90 00 } //01 00 
		$a_02_1 = {0f b6 c2 03 05 90 01 05 25 90 01 04 8a 98 90 01 04 88 90 01 05 88 99 90 01 04 0f b6 90 01 05 89 0d 90 01 04 0f b6 cb 03 ca 81 e1 90 01 04 a3 90 01 04 8a 81 90 00 } //01 00 
		$a_02_2 = {30 04 3e b8 90 01 04 29 44 24 90 01 01 8b 74 24 90 01 01 85 f6 7d 90 00 } //02 00 
		$a_02_3 = {0f b6 c2 03 05 90 01 04 89 0d 90 01 04 25 90 01 04 8a 98 90 01 04 88 90 90 01 04 88 99 90 01 04 0f b6 90 90 01 04 a3 90 01 04 0f b6 c3 03 d0 81 e2 90 01 04 8a 8a 90 01 04 30 0c 37 b8 90 01 04 29 45 90 01 01 8b 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}