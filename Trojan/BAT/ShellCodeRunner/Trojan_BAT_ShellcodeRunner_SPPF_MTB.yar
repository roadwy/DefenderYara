
rule Trojan_BAT_ShellcodeRunner_SPPF_MTB{
	meta:
		description = "Trojan:BAT/ShellcodeRunner.SPPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 0c e2 04 00 00 07 fe 0c e2 04 00 00 93 28 ?? ?? ?? 0a 9c 00 fe 0c e2 04 00 00 17 58 fe 0e e2 04 00 00 fe 0c e2 04 00 00 09 8e 69 fe 04 fe 0e e3 04 00 00 fe 0c e3 04 00 00 2d c2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}