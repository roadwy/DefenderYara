
rule Trojan_BAT_Xmrig_NMG_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.NMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {73 36 00 00 0a 13 0c 06 16 9a 7e 90 01 01 00 00 04 06 17 9a 7e 90 01 01 00 00 04 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 13 0b 11 0c 02 11 0b 02 8e b7 11 0b da 6f 90 01 01 00 00 0a 11 0c 6f 90 01 01 00 00 0a 28 90 01 01 00 00 06 0b de 36 90 00 } //01 00 
		$a_01_1 = {43 72 61 78 73 20 52 61 74 20 4c 6f 61 64 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}