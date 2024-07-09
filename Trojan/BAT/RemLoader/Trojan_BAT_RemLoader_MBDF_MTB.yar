
rule Trojan_BAT_RemLoader_MBDF_MTB{
	meta:
		description = "Trojan:BAT/RemLoader.MBDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 02 06 28 ?? ?? 00 06 72 fa 3d 04 70 72 fe 3d 04 70 6f ?? 00 00 0a 72 02 3e 04 70 72 06 3e 04 70 6f ?? 00 00 0a 0a 06 72 0c 3e 04 70 72 10 3e 04 70 6f ?? 00 00 0a 17 8d ?? 00 00 01 25 16 1f 7e 9d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}