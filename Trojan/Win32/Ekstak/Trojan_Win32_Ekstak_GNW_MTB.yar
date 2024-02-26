
rule Trojan_Win32_Ekstak_GNW_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GNW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 83 c4 14 48 89 35 dc 0c 4d 00 5f 5e a3 d8 0c 4d 00 5b c9 c3 55 8b ec 8b 4d 18 8b 45 14 53 56 83 21 00 } //00 00 
	condition:
		any of ($a_*)
 
}