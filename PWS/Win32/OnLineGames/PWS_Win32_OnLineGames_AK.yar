
rule PWS_Win32_OnLineGames_AK{
	meta:
		description = "PWS:Win32/OnLineGames.AK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f 84 91 00 00 00 6a 02 6a 00 68 4a ff ff ff 53 e8 } //1
		$a_03_1 = {8b c8 49 85 c9 72 1e 41 a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8a 18 80 c3 ?? 80 f3 ?? 80 eb ?? 88 1a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}