
rule Trojan_BAT_AsyncRAT_KAM_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.KAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 91 61 d2 9c 00 fe 09 06 00 71 ?? 00 00 01 20 01 00 00 00 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}