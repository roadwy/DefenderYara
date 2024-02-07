
rule Trojan_MacOS_Padzer_A_MTB{
	meta:
		description = "Trojan:MacOS/Padzer.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {2f 55 73 65 72 73 2f 75 73 65 72 2f 64 65 76 90 02 15 2f 6e 73 6c 61 75 6e 63 68 64 2f 6e 73 6c 61 75 6e 63 68 64 90 00 } //02 00 
		$a_00_1 = {2f 74 6d 70 2f 00 77 62 00 68 65 61 64 20 2d 63 20 00 20 2f 64 65 76 2f 7a 65 72 6f 20 3e 3e 20 00 63 68 6d 6f 64 20 2b 78 20 00 73 6c 65 65 70 20 36 30 00 26 00 0a 23 21 2f 62 69 6e 2f 62 61 73 68 } //02 00 
		$a_00_2 = {69 66 20 70 67 72 65 70 20 22 41 63 74 69 76 69 74 79 20 4d 6f 6e 69 74 6f 72 22 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c 3b 74 68 65 6e 20 6b 69 6c 6c 61 6c 6c } //01 00  if pgrep "Activity Monitor" > /dev/null;then killall
		$a_00_3 = {2f 41 70 70 6c 69 63 61 74 69 6f 6e 73 2f 46 69 6e 61 6c 5c 20 43 75 74 5c 20 50 72 6f 2e 61 70 70 2f 43 6f 6e 74 65 6e 74 73 2f 4d 61 63 4f 53 2f 2e 46 69 6e 61 6c 5c 20 43 75 74 5c 20 50 72 6f } //00 00  /Applications/Final\ Cut\ Pro.app/Contents/MacOS/.Final\ Cut\ Pro
		$a_00_4 = {5d 04 00 } //00 b6 
	condition:
		any of ($a_*)
 
}