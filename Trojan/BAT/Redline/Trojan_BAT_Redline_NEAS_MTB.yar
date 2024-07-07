
rule Trojan_BAT_Redline_NEAS_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 3b 00 00 0a 0e 06 71 3e 00 00 01 0e 09 71 3d 00 00 01 0e 06 71 3e 00 00 01 6f 3c 00 00 0a 1e 5b 6f 3a 00 00 0a 6f 3d 00 00 0a 0e 06 71 3e 00 00 01 17 6f 3e 00 00 0a 28 4e 00 00 06 0d 0e 0a 09 81 04 00 00 1b 0e 05 71 1a 00 00 01 0e 06 71 3e 00 00 01 6f 3f 00 00 0a 17 73 40 00 00 0a 13 04 0e 0b 11 04 81 38 00 00 01 02 1a 54 11 05 2a } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}