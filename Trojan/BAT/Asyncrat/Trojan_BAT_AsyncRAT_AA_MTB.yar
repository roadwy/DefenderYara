
rule Trojan_BAT_AsyncRAT_AA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 03 8e 69 0b 16 0c 07 20 ff 00 00 00 fe 02 16 fe 01 0d 09 2c 1d 00 20 c4 00 00 00 0c 02 08 6f 5b 00 00 0a 00 07 d2 0c 02 08 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}