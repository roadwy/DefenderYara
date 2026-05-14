
rule Trojan_BAT_AsyncRAT_VD_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 07 11 04 91 58 03 11 04 03 8e 69 5d 91 58 20 00 01 00 00 5d 0d 07 11 04 91 13 05 07 11 04 07 09 91 9c 07 09 11 05 9c 11 04 17 58 13 04 11 04 20 00 01 00 00 32 c9 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}