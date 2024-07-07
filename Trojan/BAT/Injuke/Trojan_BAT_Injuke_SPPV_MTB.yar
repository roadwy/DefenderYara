
rule Trojan_BAT_Injuke_SPPV_MTB{
	meta:
		description = "Trojan:BAT/Injuke.SPPV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 08 08 18 5d 2c 08 07 08 91 1f 09 61 2b 05 07 08 91 1b 61 d2 9c 08 17 58 0c 08 07 8e 69 32 e0 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}