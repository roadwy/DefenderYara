
rule PWS_Win32_OnLineGames_EQ{
	meta:
		description = "PWS:Win32/OnLineGames.EQ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 65 61 6c 6d 6c 69 73 74 2e 77 74 66 90 02 3b 2e 77 6f 72 6c 64 6f 66 77 61 72 63 72 61 66 74 2e 63 6f 6d 90 02 10 2e 77 6f 77 63 68 69 6e 61 2e 63 6f 6d 90 00 } //2
		$a_01_1 = {48 6f 6f 6b 2e 64 6c 6c 00 6b 73 48 6f 6f 6b 77 6f 00 74 7a 48 6f 6f 6b 77 6f } //1 潈歯搮汬欀䡳潯睫o穴潈歯潷
		$a_01_2 = {4c 69 75 5f 4d 61 7a 69 4e 7d 6a 51 73 72 58 32 79 64 79 90 4f 71 7d 6e 68 49 6c 32 79 64 79 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}