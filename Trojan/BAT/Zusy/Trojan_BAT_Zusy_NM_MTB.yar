
rule Trojan_BAT_Zusy_NM_MTB{
	meta:
		description = "Trojan:BAT/Zusy.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 03 11 02 ?? ?? 00 00 0a 11 04 fe 04 13 0d } //2
		$a_01_1 = {11 04 11 00 17 59 99 11 04 11 00 99 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}