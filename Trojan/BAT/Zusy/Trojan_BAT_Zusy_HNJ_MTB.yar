
rule Trojan_BAT_Zusy_HNJ_MTB{
	meta:
		description = "Trojan:BAT/Zusy.HNJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-95] 3d 00 55 00 54 00 46 00 2d 00 38 00 01 80 ad 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 35 00 2e 00 30 [0-e5] 0b 3c 00 70 00 72 00 65 00 3e 00 00 0d 3c 00 2f 00 70 00 72 00 65 00 3e 00 00 0d 26 00 71 00 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}