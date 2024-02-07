
rule Trojan_Win32_Konus_SH_MTB{
	meta:
		description = "Trojan:Win32/Konus.SH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3f 00 3f 00 0a 00 00 1e 00 "
		
	strings :
		$a_01_0 = {43 33 45 30 51 36 52 37 46 31 48 32 47 35 41 34 } //01 00  C3E0Q6R7F1H2G5A4
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 61 70 69 2e 69 70 69 66 79 2e 6f 72 67 2f } //01 00  https://api.ipify.org/
		$a_01_2 = {3f 61 3d 30 } //01 00  ?a=0
		$a_01_3 = {3f 61 3d 34 } //01 00  ?a=4
		$a_01_4 = {3f 61 3d 32 } //01 00  ?a=2
		$a_01_5 = {3f 61 3d 33 } //0a 00  ?a=3
		$a_01_6 = {3a 00 5a 00 6f 00 6e 00 65 00 2e 00 49 00 64 00 65 00 6e 00 74 00 69 00 66 00 69 00 65 00 72 00 } //0a 00  :Zone.Identifier
		$a_01_7 = {53 00 65 00 44 00 65 00 62 00 75 00 67 00 50 00 72 00 69 00 76 00 69 00 6c 00 65 00 67 00 65 00 } //0a 00  SeDebugPrivilege
		$a_01_8 = {63 00 68 00 72 00 6f 00 6d 00 65 00 2e 00 65 00 78 00 65 00 } //0a 00  chrome.exe
		$a_01_9 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //00 00  explorer.exe
	condition:
		any of ($a_*)
 
}