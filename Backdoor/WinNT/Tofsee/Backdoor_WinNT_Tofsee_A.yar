
rule Backdoor_WinNT_Tofsee_A{
	meta:
		description = "Backdoor:WinNT/Tofsee.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {2b fe 8a c1 ?? ?? b3 ?? f6 eb 8d 14 31 32 04 17 41 81 f9 ?? ?? 00 00 88 02 75 e7 } //3
		$a_03_1 = {47 47 66 3b c3 75 f5 8d ?? ?? f7 ff ff be ?? ?? ?? ?? 50 f3 a5 } //2
		$a_03_2 = {68 c0 a6 00 00 8d ?? ?? ?? ff ff 50 8d 45 ?? 50 53 } //2
		$a_00_3 = {2f 00 69 00 6e 00 64 00 65 00 78 00 2e 00 68 00 74 00 6d 00 6c 00 } //1 /index.html
		$a_01_4 = {48 6f 74 20 69 6e 74 65 72 6e 65 74 20 6f 66 66 65 72 73 00 } //1 潈⁴湩整湲瑥漠晦牥s
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}