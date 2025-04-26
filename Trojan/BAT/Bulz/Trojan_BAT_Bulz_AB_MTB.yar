
rule Trojan_BAT_Bulz_AB_MTB{
	meta:
		description = "Trojan:BAT/Bulz.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 52 00 06 28 ?? ?? ?? 06 0b 07 17 2e 0a 07 20 01 80 ff ff fe 01 2b 01 17 0c 08 2c 32 00 02 7b 04 00 00 04 17 73 10 00 00 0a 0d 02 7b 04 00 00 04 18 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}