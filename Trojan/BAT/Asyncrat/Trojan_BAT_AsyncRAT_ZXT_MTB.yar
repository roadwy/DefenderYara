
rule Trojan_BAT_AsyncRAT_ZXT_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ZXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 02 11 04 11 00 11 04 91 11 01 11 04 11 01 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 20 02 00 00 00 38 13 ff ff ff 72 01 00 00 70 13 01 20 00 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 39 f8 fe ff ff 26 20 01 00 00 00 38 ed fe ff ff 38 58 ff ff ff 20 03 00 00 00 38 de fe ff ff } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}