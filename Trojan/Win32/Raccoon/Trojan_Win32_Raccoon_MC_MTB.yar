
rule Trojan_Win32_Raccoon_MC_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.MC!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 83 65 fc 00 8b 45 0c 01 45 fc 8b 45 fc 31 45 08 8b 45 08 c9 c2 08 00 } //05 00 
		$a_01_1 = {01 08 c3 29 08 c3 } //00 00 
	condition:
		any of ($a_*)
 
}