
rule Trojan_BAT_XMRig_IJ_MTB{
	meta:
		description = "Trojan:BAT/XMRig.IJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 0e 00 00 0a 0b 06 6f 13 00 00 0a 07 28 14 00 00 0a 0c 08 6f 15 00 00 0a 7e 02 00 00 04 25 3a 17 00 00 00 26 7e 01 00 00 04 fe 06 06 00 00 06 73 16 00 00 0a 25 80 02 00 00 04 28 01 00 00 2b } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}