
rule Trojan_BAT_ReverseShell_ARL_MTB{
	meta:
		description = "Trojan:BAT/ReverseShell.ARL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0d 2b 2e 06 6f 90 01 03 0a 8d 19 00 00 01 13 05 07 11 05 16 11 05 8e 69 6f 90 01 03 0a 26 09 28 90 01 03 0a 11 05 6f 90 00 } //01 00 
		$a_01_1 = {52 00 65 00 76 00 53 00 68 00 65 00 6c 00 6c 00 41 00 49 00 } //00 00 
	condition:
		any of ($a_*)
 
}