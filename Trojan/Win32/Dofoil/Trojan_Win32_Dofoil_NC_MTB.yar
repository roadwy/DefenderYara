
rule Trojan_Win32_Dofoil_NC_MTB{
	meta:
		description = "Trojan:Win32/Dofoil.NC!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 83 65 fc 00 8b 45 0c 89 45 fc 8b 45 08 31 45 fc 8b 45 fc 89 01 c9 c2 08 00 55 8b ec 51 83 65 fc 00 8b 45 0c 01 45 fc 8b 45 fc 31 45 08 8b 45 08 c9 c2 08 00 } //00 00 
	condition:
		any of ($a_*)
 
}