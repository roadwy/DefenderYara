
rule Trojan_BAT_DonutLoader_SJ_MTB{
	meta:
		description = "Trojan:BAT/DonutLoader.SJ!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 0b 00 00 70 72 05 00 00 70 6f 11 00 00 0a 72 0f 00 00 70 72 05 00 00 70 6f 11 00 00 0a 10 02 03 28 12 00 00 0a 0a 04 28 12 00 00 0a 0b 28 13 00 00 0a 0c 08 06 6f 14 00 00 0a 08 07 6f 15 00 00 0a 08 17 6f 16 00 00 0a 08 18 6f 17 00 00 0a 73 18 00 00 0a 0d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}