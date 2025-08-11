
rule Trojan_BAT_Jalapeno_BQ_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 07 00 20 71 c8 34 2c 5a 20 37 d3 b1 53 61 2b 22 fe 0c 07 00 20 cd 4a e5 67 5a 20 3a 15 76 73 61 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}