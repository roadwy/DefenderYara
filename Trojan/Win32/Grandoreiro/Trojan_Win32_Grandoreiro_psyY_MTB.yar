
rule Trojan_Win32_Grandoreiro_psyY_MTB{
	meta:
		description = "Trojan:Win32/Grandoreiro.psyY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 8b 45 08 a3 6f 42 40 00 68 c4 30 40 00 ff 15 60 30 40 00 6a 00 8b 4d 08 51 6a 00 6a 00 6a 00 68 00 00 00 80 6a 00 68 00 00 00 80 68 00 00 cf 00 68 00 40 40 00 68 0c 40 40 00 6a 00 ff 15 80 30 40 00 89 45 fc 83 7d fc 00 75 04 33 c0 eb 1b 6a 00 8b 55 fc 52 ff 15 84 30 40 00 8b 45 fc 50 ff 15 88 30 40 00 b8 01 00 00 00 8b e5 5d c3 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}