
rule Trojan_BAT_XLoader_SVPF_MTB{
	meta:
		description = "Trojan:BAT/XLoader.SVPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {95 11 04 11 06 95 58 20 ff 00 00 00 5f 13 0b 11 0b 1f 7b 61 20 ff 00 00 00 5f 13 0c 11 0c 20 c8 01 00 00 58 20 00 01 00 00 5e 13 0c 11 0c 16 fe 01 13 0d } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}