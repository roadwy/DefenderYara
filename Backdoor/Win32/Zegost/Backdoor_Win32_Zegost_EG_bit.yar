
rule Backdoor_Win32_Zegost_EG_bit{
	meta:
		description = "Backdoor:Win32/Zegost.EG!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 10 25 90 01 04 99 b9 90 01 04 f7 f9 90 02 10 88 55 fc c7 45 f8 00 00 00 00 eb 90 01 01 8b 55 f8 83 c2 01 89 55 f8 8b 45 f8 3b 45 0c 73 90 01 01 8b 4d 08 8a 11 32 55 fc 8b 45 08 88 10 8b 4d 08 8a 11 02 55 fc 8b 45 08 88 10 8b 4d 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}