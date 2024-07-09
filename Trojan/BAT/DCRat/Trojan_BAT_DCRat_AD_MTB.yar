
rule Trojan_BAT_DCRat_AD_MTB{
	meta:
		description = "Trojan:BAT/DCRat.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 2d 07 15 2c 04 2b 4d 2b 52 1c 2c 31 16 2b 4f 2b 2c 2b 4e 2b 4f 72 ?? ?? ?? 70 2b 4f 2b 54 2b 55 72 ?? ?? ?? 70 2b 55 8e 69 5d 91 7e ?? ?? ?? 04 07 91 61 d2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}