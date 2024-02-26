
rule Trojan_BAT_ShellcodeRunner_KAA_MTB{
	meta:
		description = "Trojan:BAT/ShellcodeRunner.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {00 08 fe 0c c2 04 00 00 07 fe 0c c2 04 00 00 93 28 90 01 01 00 00 0a 9c 00 fe 0c c2 04 00 00 17 58 fe 0e c2 04 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}