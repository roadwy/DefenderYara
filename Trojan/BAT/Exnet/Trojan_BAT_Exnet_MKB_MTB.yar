
rule Trojan_BAT_Exnet_MKB_MTB{
	meta:
		description = "Trojan:BAT/Exnet.MKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 28 1d 00 00 0a 0a de 03 26 de 45 06 6f 1e 00 00 0a 0b 16 0c 2b 34 07 08 9a ?? ?? 00 00 70 1f 18 6f 1f 00 00 0a } //20
		$a_01_1 = {07 6f 10 00 00 0a 08 17 6f 11 00 00 0a 08 17 6f 12 00 00 0a 08 16 6f 13 00 00 0a 08 16 6f 14 00 00 0a 08 20 ff ff 00 00 1e } //15
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*15) >=35
 
}