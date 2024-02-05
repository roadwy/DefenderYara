
rule Trojan_Win32_DarkComet_AME_MTB{
	meta:
		description = "Trojan:Win32/DarkComet.AME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 d4 8b 4d e8 2b 48 14 8b 45 d4 8b 40 0c 8b 55 d8 8b 75 e4 2b 72 14 8b 55 d8 8b 52 0c 8a 04 08 32 04 32 8b 4d d4 8b 55 e8 2b 51 14 8b 4d d4 8b 49 0c 88 04 11 8b 45 e4 40 89 45 e4 8b 45 e4 3b 45 e0 7e 04 83 65 e4 00 8b 45 e8 40 89 45 e8 } //00 00 
	condition:
		any of ($a_*)
 
}