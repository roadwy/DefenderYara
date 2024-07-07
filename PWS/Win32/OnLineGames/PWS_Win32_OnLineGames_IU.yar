
rule PWS_Win32_OnLineGames_IU{
	meta:
		description = "PWS:Win32/OnLineGames.IU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {60 ea 00 00 c7 44 24 90 01 01 00 00 00 00 c7 44 24 90 01 01 d8 c4 c4 c0 c7 44 24 90 01 01 bf a1 be a1 c7 44 24 90 01 01 b0 a2 a0 a0 c7 44 24 90 01 01 90 90 90 90 90 90 90 90 c7 44 24 90 01 01 d7 d5 c4 90 90 c7 44 24 90 01 01 d1 f3 f3 f5 90 00 } //1
		$a_01_1 = {32 30 35 2e 32 30 39 2e 31 36 31 2e 31 31 30 } //1 205.209.161.110
		$a_03_2 = {54 4e 53 48 90 02 0a 2d 53 51 59 50 4c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}