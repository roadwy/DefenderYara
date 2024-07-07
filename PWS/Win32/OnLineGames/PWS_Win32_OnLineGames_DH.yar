
rule PWS_Win32_OnLineGames_DH{
	meta:
		description = "PWS:Win32/OnLineGames.DH,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 73 68 65 6c 6c 65 78 65 63 75 74 65 68 6f 6f 6b 73 } //1 currentversion\Explorer\shellexecutehooks
		$a_01_1 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //1 SeDebugPrivilege
		$a_01_2 = {25 73 5c 46 4f 6e 74 73 5c 25 73 2e 74 74 66 } //1 %s\FOnts\%s.ttf
		$a_01_3 = {26 50 49 4e 3d 25 73 26 52 3d 25 73 26 52 47 3d 25 64 26 4d 3d 25 64 26 4d 31 3d 25 64 26 6d 61 63 3d 25 73 } //1 &PIN=%s&R=%s&RG=%d&M=%d&M1=%d&mac=%s
		$a_01_4 = {63 6f 6e 6e 65 63 74 00 72 65 63 76 } //1 潣湮捥t敲癣
		$a_01_5 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 69 67 61 6d 65 63 6c 69 65 6e 74 } //1 User-Agent: igameclient
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}