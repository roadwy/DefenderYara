
rule Trojan_BAT_AsyncRAT_ZKY_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ZKY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {58 20 00 01 00 00 5d 94 fe 0e 0e 00 fe 0c 07 00 fe 0c 0c 00 fe 09 00 00 fe 0c 0c 00 91 fe 0c 0e 00 61 28 ?? 00 00 0a 9c fe 0c 0c 00 20 01 00 00 00 58 fe 0e 0c 00 fe 0c 0c 00 fe 09 00 00 8e 69 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}