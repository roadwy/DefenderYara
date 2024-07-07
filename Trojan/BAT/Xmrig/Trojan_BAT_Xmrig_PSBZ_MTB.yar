
rule Trojan_BAT_Xmrig_PSBZ_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.PSBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 06 02 07 1e 6f 39 90 01 03 18 28 3a 90 01 03 6f 3b 90 01 03 00 00 07 1e 58 0b 07 02 6f 3c 90 01 03 fe 04 0c 08 2d d8 28 3d 90 01 03 06 6f 3e 90 01 03 6f 3f 90 01 03 0d 2b 00 09 2a 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}