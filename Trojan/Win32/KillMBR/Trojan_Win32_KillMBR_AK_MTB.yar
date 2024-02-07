
rule Trojan_Win32_KillMBR_AK_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 6f 72 61 6e 32 2d 20 4d 61 6c 77 61 72 65 20 41 6c 65 72 74 } //01 00  Coran2- Malware Alert
		$a_01_1 = {64 61 6e 67 65 72 6f 75 73 2c 20 69 74 20 63 61 6e 20 64 65 6c 65 74 65 20 63 69 2e 64 6c 6c 20 61 6e 64 20 65 74 63 2c 20 61 6c 73 6f 20 69 74 20 63 61 6e 20 6f 76 65 72 77 72 69 74 65 20 79 6f 75 72 20 4d 42 52 20 74 68 61 74 20 77 69 6c 6c 20 6d 61 6b 65 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 75 6e 75 73 61 62 6c 65 } //01 00  dangerous, it can delete ci.dll and etc, also it can overwrite your MBR that will make your computer unusable
		$a_01_2 = {77 61 6e 74 20 74 6f 20 72 75 6e 20 74 68 69 73 3f 20 54 68 69 73 20 69 73 20 73 75 70 65 72 20 64 61 6e 67 65 72 6f 75 73 20 61 73 20 66 75 63 6b 2c 20 73 6f 20 69 66 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 6b 65 65 } //01 00  want to run this? This is super dangerous as fuck, so if you want to kee
		$a_01_3 = {49 66 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 6b 65 65 70 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 73 61 66 65 20 66 72 6f 6d 20 74 68 65 73 65 20 64 65 73 74 72 75 63 74 69 6f 6e 20 63 72 65 61 74 65 64 20 62 79 20 74 68 69 73 20 6d 61 6c 77 61 72 65 20 6a 75 73 74 20 70 72 65 73 20 5b 4e 6f 5d 20 74 6f 20 65 78 69 74 } //01 00  If you want to keep your computer safe from these destruction created by this malware just pres [No] to exit
		$a_01_4 = {4c 61 73 74 20 57 61 72 6e 69 6e 67 2d 20 59 6f 75 20 70 72 65 73 73 65 64 20 5b 59 65 73 5d 20 74 6f 20 74 68 65 20 66 69 72 73 74 20 77 61 72 6e 69 6e 67 2c 20 62 75 74 20 77 68 79 20 64 69 64 20 79 6f 75 } //00 00  Last Warning- You pressed [Yes] to the first warning, but why did you
	condition:
		any of ($a_*)
 
}