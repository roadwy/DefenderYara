
rule Trojan_Win32_Stealer_ER_MTB{
	meta:
		description = "Trojan:Win32/Stealer.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8a 0c 86 8b 45 fc 8b 7d 08 32 0c 38 8b 7d fc 8b 86 00 08 00 00 88 0c 07 8b c7 8b 7d 0c 40 89 45 fc } //00 00 
	condition:
		any of ($a_*)
 
}