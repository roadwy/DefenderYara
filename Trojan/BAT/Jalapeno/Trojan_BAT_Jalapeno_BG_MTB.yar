
rule Trojan_BAT_Jalapeno_BG_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 6e 20 ff 00 00 00 6a 5f b7 95 03 50 7b 6c 00 00 04 1e 64 61 7d 6c 00 00 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}