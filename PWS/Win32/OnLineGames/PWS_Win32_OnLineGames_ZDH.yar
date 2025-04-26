
rule PWS_Win32_OnLineGames_ZDH{
	meta:
		description = "PWS:Win32/OnLineGames.ZDH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {45 6c 65 6d c7 45 ?? 65 6e 74 43 c7 45 ?? 6c 69 65 6e c7 45 ?? 74 2e 65 78 c7 45 ?? 65 00 00 00 } //1
		$a_02_1 = {77 6f 77 2e ?? ?? c7 45 ?? 65 78 65 00 } //1
		$a_02_2 = {5c 6d 70 70 c7 45 ?? 64 73 2e 64 c7 45 ?? 6c 6c 00 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}