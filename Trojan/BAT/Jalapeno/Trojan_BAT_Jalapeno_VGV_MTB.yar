
rule Trojan_BAT_Jalapeno_VGV_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.VGV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 11 06 7e 01 00 00 04 11 06 91 20 82 00 00 00 61 d2 9c 11 06 17 58 13 06 20 0f 00 68 33 fe 0e 0a 00 fe 0d 0a 00 00 48 68 d3 13 09 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}