
rule Trojan_BAT_ShellCodeRunner_GAF_MTB{
	meta:
		description = "Trojan:BAT/ShellCodeRunner.GAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2f 00 4f 00 69 00 50 00 41 00 41 00 41 00 41 00 59 00 44 00 48 00 53 00 69 00 65 00 56 00 6b 00 69 00 31 00 49 00 3d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}