
rule Trojan_BAT_Heracles_MBZB_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MBZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {09 08 5d 13 90 01 01 07 11 90 01 01 91 11 90 01 01 09 1f 90 01 01 5d 91 61 13 90 01 01 1f 90 01 01 13 90 00 } //01 00 
		$a_01_1 = {09 11 06 91 11 08 11 04 1f 16 5d 91 61 13 0c 1f 0d 0a } //00 00 
	condition:
		any of ($a_*)
 
}