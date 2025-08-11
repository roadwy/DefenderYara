
rule Trojan_BAT_AsyncRAT_GVC_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {39 0d 00 00 00 fe 0c 00 00 fe 09 00 00 6f f2 00 00 0a fe 0c 00 00 fe 09 00 00 fe 09 01 00 6f ae 00 00 0a dd 13 00 00 00 fe 0c 00 00 39 09 00 00 00 fe 0c 00 00 6f 1a 00 00 0a dc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}