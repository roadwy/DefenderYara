
rule Trojan_BAT_Injuke_AKCA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AKCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 06 8f 26 00 00 01 25 71 26 00 00 01 1f ?? 59 d2 81 26 00 00 01 08 20 } //3
		$a_03_1 = {02 06 8f 26 00 00 01 25 71 26 00 00 01 1f ?? 59 d2 81 26 00 00 01 08 } //2
		$a_01_2 = {02 06 02 06 91 66 d2 9c } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}