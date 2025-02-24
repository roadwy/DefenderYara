
rule Trojan_BAT_DcRat_PLLBH_MTB{
	meta:
		description = "Trojan:BAT/DcRat.PLLBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 09 02 09 91 06 08 91 61 09 20 00 01 00 00 5d 61 d2 9c 08 07 09 91 06 8e 69 5d 58 06 8e 69 5d 0c 09 17 58 0d 09 02 8e 69 32 d5 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}