
rule Trojan_BAT_Starter_ARR_MTB{
	meta:
		description = "Trojan:BAT/Starter.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {0b 14 0c 06 08 25 2d 04 26 09 2b 0a } //8 ᐋ،┈Эदਫ
		$a_81_1 = {54 61 62 54 69 70 50 72 6f 78 79 2e 65 78 65 } //12 TabTipProxy.exe
	condition:
		((#a_01_0  & 1)*8+(#a_81_1  & 1)*12) >=20
 
}