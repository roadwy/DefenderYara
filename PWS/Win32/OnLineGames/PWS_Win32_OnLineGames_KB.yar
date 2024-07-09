
rule PWS_Win32_OnLineGames_KB{
	meta:
		description = "PWS:Win32/OnLineGames.KB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {c6 00 60 2b ?? c6 40 01 54 83 ?? 07 c6 40 02 e8 89 ?? 03 c6 40 07 61 } //1
		$a_01_1 = {83 ea 05 89 54 24 04 8b 54 24 14 2b d0 c6 00 e9 83 ea 05 } //1
		$a_00_2 = {73 65 6e 64 75 73 65 72 3d 25 73 26 72 65 63 65 69 76 65 75 73 65 72 3d 25 73 26 6d 6f 6e 65 79 3d 25 73 } //1 senduser=%s&receiveuser=%s&money=%s
		$a_00_3 = {00 73 74 72 70 61 73 73 77 6f 72 64 3d } //1
		$a_00_4 = {55 3d 25 73 2b 50 3d 25 73 2b 50 32 3d 25 73 2b 53 3d 4d 53 2b 41 3d 25 73 2b 52 3d 25 73 2b 47 3d 25 64 } //1 U=%s+P=%s+P2=%s+S=MS+A=%s+R=%s+G=%d
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}