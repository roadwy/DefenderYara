
rule Trojan_BAT_Zusy_SN{
	meta:
		description = "Trojan:BAT/Zusy.SN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 01 11 05 16 11 06 6f 0b 00 00 0a 38 00 00 00 00 11 04 11 05 16 11 05 8e 69 6f 0c 00 00 0a 25 13 06 16 3d d8 ff ff ff 38 0a 00 00 00 38 df ff ff ff 38 c9 ff ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}