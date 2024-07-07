
rule Backdoor_Win32_CobaltStrike_BW_dha{
	meta:
		description = "Backdoor:Win32/CobaltStrike.BW!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 48 83 ec 30 c7 45 fc 00 00 00 00 c7 45 f8 00 00 00 00 c7 45 f4 00 00 00 00 c7 45 f0 c0 d4 01 00 48 8b 05 16 0a 11 00 } //1
		$a_01_1 = {ff d0 89 45 fc 8b 45 f0 89 c1 48 8b 05 c5 0a 11 00 ff d0 48 8b 05 fc 09 11 00 ff d0 89 45 f8 8b 45 f8 2b 45 fc 89 45 f4 8b 45 f0 2d e8 03 00 00 39 45 f4 76 07 b8 00 00 00 00 eb 05 b8 01 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}