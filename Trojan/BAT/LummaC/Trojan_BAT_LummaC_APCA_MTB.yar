
rule Trojan_BAT_LummaC_APCA_MTB{
	meta:
		description = "Trojan:BAT/LummaC.APCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 06 8f 26 00 00 01 25 71 26 00 00 01 1f 45 59 d2 81 26 00 00 01 02 06 8f 26 00 00 01 25 71 26 00 00 01 1f 29 59 d2 81 26 00 00 01 00 08 } //3
		$a_01_1 = {02 06 02 06 91 66 d2 9c } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}