
rule Trojan_BAT_AveMariaRat_YIVF_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRat.YIVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 8e 69 5d 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 90 01 03 0a 03 08 18 58 17 59 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}