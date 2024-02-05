
rule Trojan_BAT_RedLine_MTB{
	meta:
		description = "Trojan:BAT/RedLine!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {73 64 69 38 34 35 73 61 } //00 00 
	condition:
		any of ($a_*)
 
}