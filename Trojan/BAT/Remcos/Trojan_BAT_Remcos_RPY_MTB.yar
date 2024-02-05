
rule Trojan_BAT_Remcos_RPY_MTB{
	meta:
		description = "Trojan:BAT/Remcos.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {fe 0c 01 00 6f 67 00 00 0a 20 03 00 00 00 66 20 02 00 00 00 63 65 8d 2e 00 00 01 25 20 40 fc 9e 24 20 bf 03 61 db 58 66 20 b4 be 87 e7 20 01 00 00 00 63 66 20 9e 20 3c 0c 61 9d 6f 68 00 00 0a fe 0e 02 00 20 1c 00 00 00 38 43 e8 ff ff } //00 00 
	condition:
		any of ($a_*)
 
}