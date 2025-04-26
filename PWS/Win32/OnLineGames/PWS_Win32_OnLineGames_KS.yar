
rule PWS_Win32_OnLineGames_KS{
	meta:
		description = "PWS:Win32/OnLineGames.KS,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {5b 64 6e 74 5d bc d3 d4 d8 64 6c 6c b3 c9 b9 a6 a3 a1 00 00 5b 64 6e 74 5d bc d3 d4 d8 64 6c 6c [0-10] 72 62 00 00 5c 64 64 72 [0-04] 2e 6f 63 78 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}