
rule Trojan_Win32_Grandoreiro_psyX_MTB{
	meta:
		description = "Trojan:Win32/Grandoreiro.psyX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {55 8b ec 81 ec 1c 02 00 00 8b 45 08 89 85 f4 fd ff ff 8b 4d 0c 89 8d e4 fd ff ff c7 85 e8 fd ff ff 05 00 00 00 c7 85 f0 fd ff ff c0 90 43 00 8b 95 f4 fd ff ff 3b 95 e4 fd ff ff 73 14 c7 85 e8 fd ff ff 05 00 00 00 8b 85 f4 fd ff ff eb 12 eb 10 c7 85 e8 fd ff ff 05 00 00 00 8b 85 e4 fd ff ff 8b e5 5d } //00 00 
	condition:
		any of ($a_*)
 
}