
rule Trojan_Win32_Convagent_AV_MTB{
	meta:
		description = "Trojan:Win32/Convagent.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 45 2c a2 86 7a 5c c7 45 68 6e b7 1b 45 c7 85 90 02 04 af 55 a9 41 89 55 70 b8 3b 2d 0b 00 01 45 70 8b 45 70 8a 04 30 88 04 0e 46 3b 35 90 02 04 0f 82 90 00 } //01 00 
		$a_01_1 = {c7 45 b8 39 61 cd 71 c7 45 74 66 25 52 4c c7 45 60 92 48 22 70 c7 45 18 7f 17 c5 44 c7 45 20 f6 01 72 35 c7 45 c4 f0 4e f3 3e } //01 00 
		$a_01_2 = {81 ff a7 b4 e7 00 7f 0d 47 81 ff e2 99 4e 5d 0f 8c } //01 00 
		$a_01_3 = {77 6f 72 6d 73 2e 74 78 74 } //00 00  worms.txt
	condition:
		any of ($a_*)
 
}