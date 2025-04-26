
rule Trojan_Win32_BlackMoon_DL_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 39 06 19 06 08 23 06 10 08 30 06 } //1 㤱ᤆࠆأࠐذ
	condition:
		((#a_01_0  & 1)*1) >=1
 
}