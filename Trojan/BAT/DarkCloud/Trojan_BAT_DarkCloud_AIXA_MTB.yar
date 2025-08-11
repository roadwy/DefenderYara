
rule Trojan_BAT_DarkCloud_AIXA_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.AIXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 00 11 03 02 11 03 91 03 11 03 11 01 5d 6f ?? 00 00 0a 61 d2 9c 20 } //4
		$a_01_1 = {11 03 17 58 13 03 20 } //2
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*2) >=6
 
}