
rule Trojan_BAT_LummaStealer_SWA_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0d 11 17 11 19 28 ?? 01 00 0a 25 13 1c 11 1c 4a 11 0b 11 17 11 1b 28 ?? 01 00 0a 11 0c 11 1b 11 19 28 ?? 01 00 0a d8 d6 54 11 1b 17 d6 13 1b 11 1b 11 1a 31 ca } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}