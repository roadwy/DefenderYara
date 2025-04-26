
rule Trojan_BAT_PureLogStealer_LXAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.LXAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 06 17 58 08 5d 13 09 } //2 ؑ堗崈ओ
		$a_01_1 = {07 11 06 91 11 08 61 07 11 09 91 59 20 00 01 00 00 58 13 0a } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}