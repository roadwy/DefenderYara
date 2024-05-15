
rule Trojan_BAT_LummaStealer_RPZ_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 47 09 11 0c 91 61 d2 52 11 0a 17 58 13 0a 11 0a 03 8e 69 32 a5 11 09 17 58 13 09 11 09 17 32 95 2a } //00 00 
	condition:
		any of ($a_*)
 
}