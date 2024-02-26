
rule Trojan_BAT_Remos_AMBA_MTB{
	meta:
		description = "Trojan:BAT/Remos.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {08 11 06 1f 16 5d 91 13 0c 07 11 0a 91 11 07 58 13 0d 11 0b 11 0c 61 13 0e } //00 00 
	condition:
		any of ($a_*)
 
}