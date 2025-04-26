
rule PWS_Win32_OnLineGames_ZFV{
	meta:
		description = "PWS:Win32/OnLineGames.ZFV,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 10 80 c3 ?? 88 1c 10 40 3b c1 7c f2 5b c3 } //10
		$a_01_1 = {65 64 76 6c 66 6c 71 69 72 31 64 76 73 } //1 edvlflqir1dvs
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}