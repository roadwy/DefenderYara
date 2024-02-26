
rule Trojan_BAT_Tedy_PTBY_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PTBY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 06 28 40 00 00 0a 02 6f 41 00 00 0a 6f 42 00 00 0a 0b 73 35 00 00 0a 0c 16 0d 2b 1e } //00 00 
	condition:
		any of ($a_*)
 
}