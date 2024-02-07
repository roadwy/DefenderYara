
rule Trojan_Win32_DarkTrack_PA_MTB{
	meta:
		description = "Trojan:Win32/DarkTrack.PA!MTB,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 07 00 00 05 00 "
		
	strings :
		$a_01_0 = {30 38 30 49 41 4d 30 31 30 30 31 30 44 41 52 38 4b 38 39 54 52 33 53 44 54 41 43 4b } //01 00  080IAM010010DAR8K89TR3SDTACK
		$a_01_1 = {4c 6f 63 61 6c 20 56 69 63 74 69 6d } //01 00  Local Victim
		$a_01_2 = {41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 } //01 00  AntiVirusProduct
		$a_01_3 = {5c 59 61 6e 64 65 78 5c 59 61 6e 64 65 78 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //01 00  \Yandex\YandexBrowser\User Data\Default\Login Data
		$a_01_4 = {5c 43 6f 6d 6f 64 6f 5c 44 72 61 67 6f 6e 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //01 00  \Comodo\Dragon\User Data\Default\Login Data
		$a_01_5 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //01 00  \Google\Chrome\User Data\Default\Login Data
		$a_01_6 = {5c 53 6b 79 70 65 5c } //00 00  \Skype\
		$a_01_7 = {00 5d 04 00 00 } //38 26 
	condition:
		any of ($a_*)
 
}