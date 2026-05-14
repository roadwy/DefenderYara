
rule Backdoor_Win64_AdaptixC2_MK_MTB{
	meta:
		description = "Backdoor:Win64/AdaptixC2.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 10 89 4d 10 c7 ?? ?? ?? ?? ?? ?? 8b 45 10 89 45 f8 48 8d 45 fc 0f b6 00 3c dd 75 37 48 8d 45 f8 0f b6 55 13 88 10 48 8d 45 f8 48 83 c0 01 0f b6 55 12 88 10 48 8d 45 f8 48 83 c0 02 } //25
		$a_01_1 = {83 c0 02 89 c2 b8 ab aa aa aa 48 0f af c2 48 c1 e8 20 d1 e8 c1 e0 02 83 c0 01 89 45 fc 8b 45 fc 48 89 c2 b9 40 } //15
		$a_01_2 = {63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 22 22 20 2f 42 20 25 73 } //10 cmd.exe /c start "" /B %s
	condition:
		((#a_03_0  & 1)*25+(#a_01_1  & 1)*15+(#a_01_2  & 1)*10) >=50
 
}