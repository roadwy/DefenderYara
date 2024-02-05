
rule Trojan_BAT_Loki_NEB_MTB{
	meta:
		description = "Trojan:BAT/Loki.NEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0c 06 08 6f 1d 00 00 0a 06 18 6f 1e 00 00 0a 02 0d 06 6f 1f 00 00 0a 09 16 } //01 00 
		$a_01_1 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}