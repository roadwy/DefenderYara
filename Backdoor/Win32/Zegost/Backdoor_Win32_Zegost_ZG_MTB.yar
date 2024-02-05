
rule Backdoor_Win32_Zegost_ZG_MTB{
	meta:
		description = "Backdoor:Win32/Zegost.ZG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 11 32 55 fc 8b 45 08 88 10 8b 4d 08 8a 11 02 55 fc 8b 45 08 88 10 8b 4d 08 8a 11 32 55 fc 8b 45 08 88 10 8b 4d 08 83 c1 01 89 4d 08 eb } //00 00 
	condition:
		any of ($a_*)
 
}