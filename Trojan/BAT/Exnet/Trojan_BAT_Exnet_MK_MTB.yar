
rule Trojan_BAT_Exnet_MK_MTB{
	meta:
		description = "Trojan:BAT/Exnet.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {39 1d 00 00 00 26 20 05 00 00 00 38 12 00 00 00 38 c7 ff ff ff 20 00 00 00 00 fe 0e 00 00 fe 0c 00 00 45 01 00 00 00 13 00 00 00 fe 0c 00 00 20 dc 03 00 00 3b e5 ff ff ff 38 00 00 00 00 2a } //15
		$a_01_1 = {26 20 01 00 00 00 38 12 00 00 00 38 c7 ff ff ff 20 00 00 00 00 fe 0e 00 00 fe 0c 00 00 45 01 00 00 00 13 00 00 00 fe 0c 00 00 20 dc 03 00 00 3b e5 ff ff ff 38 00 00 00 00 00 2a } //10
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}