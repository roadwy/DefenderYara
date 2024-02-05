
rule Trojan_BAT_Obfuscator_WFL_MTB{
	meta:
		description = "Trojan:BAT/Obfuscator.WFL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_81_0 = {73 72 6e 79 6a 65 6a 6e 65 74 64 6e 72 74 73 67 78 7a 67 64 74 6a 7a 6a 64 67 } //01 00 
		$a_81_1 = {24 35 44 36 32 37 45 34 37 2d 36 36 45 33 2d 34 36 33 35 2d 42 39 43 32 2d 34 39 41 43 30 42 35 45 43 30 44 39 } //00 00 
	condition:
		any of ($a_*)
 
}