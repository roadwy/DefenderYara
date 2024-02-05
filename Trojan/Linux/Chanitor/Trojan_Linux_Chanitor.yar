
rule Trojan_Linux_Chanitor{
	meta:
		description = "Trojan:Linux/Chanitor,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {39 31 2e 32 32 30 2e 31 33 31 2e 31 31 34 2f 75 70 64 2f 69 6e 73 74 61 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}