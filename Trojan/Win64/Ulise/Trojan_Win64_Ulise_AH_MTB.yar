
rule Trojan_Win64_Ulise_AH_MTB{
	meta:
		description = "Trojan:Win64/Ulise.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 8b c8 33 d2 48 63 c5 ff c5 48 f7 f1 42 8a 04 32 30 06 48 ff c6 8b 05 ?? ?? ?? ?? 3b e8 72 } //30
		$a_03_1 = {48 2b c8 0f b6 84 19 ?? ?? ?? ?? 41 30 00 41 ff c1 4d 8d 40 ?? 8b 0d ?? ?? ?? ?? 44 3b c9 72 } //30
		$a_01_2 = {25 4c 4f 43 41 4c 41 50 50 44 41 54 41 25 5c 72 65 73 6f 75 72 63 65 73 5c 75 70 64 2e 61 73 61 72 } //20 %LOCALAPPDATA%\resources\upd.asar
		$a_81_3 = {35 2e 36 2e 34 70 34 72 37 31 38 31 2e 77 64 5f 32 34 31 32 33 30 5f 37 33 30 36 36 37 34 38 30 37 32 33 } //10 5.6.4p4r7181.wd_241230_730667480723
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*30+(#a_01_2  & 1)*20+(#a_81_3  & 1)*10) >=60
 
}