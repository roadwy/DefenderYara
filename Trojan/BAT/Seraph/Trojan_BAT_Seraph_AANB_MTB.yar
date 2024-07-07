
rule Trojan_BAT_Seraph_AANB_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AANB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 06 08 91 7e 90 01 01 01 00 04 7e 90 01 01 00 00 04 20 7f be 66 06 28 90 01 01 02 00 06 28 90 01 01 03 00 06 59 d2 9c 08 17 58 16 2c 12 26 08 06 8e 69 32 d2 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}