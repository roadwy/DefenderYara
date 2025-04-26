
rule Trojan_BAT_LummaStealer_CCIQ_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.CCIQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1b 62 fe 0c ?? 00 59 fe 0c ?? 00 61 fe 0c 1a 00 58 fe 0e 1a 00 fe 0c 1a 00 76 6c 6d 58 13 37 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}