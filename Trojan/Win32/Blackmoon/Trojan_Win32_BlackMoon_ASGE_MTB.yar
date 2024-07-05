
rule Trojan_Win32_BlackMoon_ASGE_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.ASGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {68 06 00 00 00 e8 90 01 03 00 83 c4 04 89 45 f8 89 65 f0 ff 75 f8 ff 15 90 02 07 90 90 39 65 f0 74 90 00 } //02 00 
		$a_03_1 = {41 51 50 3b c8 0f 8f 26 00 00 00 89 65 f0 ff 75 f8 ff 15 90 02 07 90 90 39 65 f0 74 90 00 } //01 00 
		$a_01_2 = {31 32 32 2e 32 32 34 2e 33 32 2e 38 3a 37 39 2f 68 6f 73 74 73 2f 6d 79 68 6f 73 74 73 2e 74 78 74 2e 74 78 74 } //01 00  122.224.32.8:79/hosts/myhosts.txt.txt
		$a_01_3 = {62 6c 61 63 6b 6d 6f 6f 6e } //01 00  blackmoon
		$a_01_4 = {35 42 35 32 35 32 34 36 30 42 30 38 44 33 42 32 38 32 43 33 37 45 35 45 37 41 34 36 30 45 31 38 } //00 00  5B5252460B08D3B282C37E5E7A460E18
	condition:
		any of ($a_*)
 
}