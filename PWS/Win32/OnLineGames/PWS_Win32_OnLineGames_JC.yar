
rule PWS_Win32_OnLineGames_JC{
	meta:
		description = "PWS:Win32/OnLineGames.JC,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 62 69 6e 5c 67 61 6d 65 63 6c 69 65 6e 74 2e 65 78 65 } //1 \bin\gameclient.exe
		$a_01_1 = {25 73 5c 25 64 25 64 5f 72 65 73 2e 74 6d 70 } //1 %s\%d%d_res.tmp
		$a_01_2 = {76 63 64 2e 65 78 65 } //1 vcd.exe
		$a_03_3 = {6a 40 52 03 f0 56 51 ff 15 90 01 04 8b 4c 24 1c 8b 44 24 24 83 c1 28 48 89 4c 24 1c 89 44 24 24 75 95 8b 8c 24 5c 02 00 00 8d 54 24 28 52 8b 54 24 10 6a 04 8d 44 24 28 50 83 c1 08 51 52 c7 84 24 cc 01 00 00 07 00 01 00 ff 15 90 01 04 85 c0 0f 84 5b fe ff ff 8b 44 24 20 8b 8c 24 e8 00 00 00 03 c8 8b 44 24 10 8d 94 24 b8 01 00 00 52 50 89 8c 24 70 02 00 00 ff 15 90 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*2) >=5
 
}