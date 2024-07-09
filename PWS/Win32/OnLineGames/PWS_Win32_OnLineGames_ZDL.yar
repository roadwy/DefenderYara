
rule PWS_Win32_OnLineGames_ZDL{
	meta:
		description = "PWS:Win32/OnLineGames.ZDL,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {67 6f 74 6f 20 74 72 79 20 [0-10] 69 66 20 65 78 69 73 74 20 25 73 [0-10] 64 65 6c 20 25 73 [0-10] 3a 74 72 79 [0-10] 2e 62 61 74 [0-ff] 48 4d 5f 4d 45 53 53 [0-10] 4c 4c [0-50] 2e 73 79 73 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}