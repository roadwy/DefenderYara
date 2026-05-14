
rule Trojan_BAT_Lokibot_PAB_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 11 04 11 05 28 08 03 00 06 13 06 08 12 06 28 cf 00 00 0a 8c 93 00 00 01 28 09 03 00 06 26 00 11 05 17 58 13 05 11 05 07 28 0a 03 00 06 fe 04 13 07 11 07 2d c9 } //4
		$a_81_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_01_0  & 1)*4+(#a_81_1  & 1)*1) >=5
 
}