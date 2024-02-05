
rule Trojan_BAT_Netwire_NEC_MTB{
	meta:
		description = "Trojan:BAT/Netwire.NEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 b6 00 00 06 02 03 28 1d 00 00 0a 28 b0 00 00 06 6f 1e 00 00 0a } //01 00 
		$a_01_1 = {53 00 58 00 64 00 48 00 54 00 47 00 52 00 33 00 54 00 30 00 45 00 30 00 56 00 31 00 68 00 6b 00 57 00 58 00 64 00 44 00 53 00 46 00 45 00 7a 00 4d 00 54 00 6c 00 4e 00 4f 00 45 00 77 00 31 00 52 00 30 00 74 00 30 00 61 00 47 00 70 00 46 00 59 00 33 00 6b 00 3d 00 } //00 00 
	condition:
		any of ($a_*)
 
}