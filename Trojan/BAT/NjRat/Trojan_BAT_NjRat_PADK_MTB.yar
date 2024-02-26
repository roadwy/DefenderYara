
rule Trojan_BAT_NjRat_PADK_MTB{
	meta:
		description = "Trojan:BAT/NjRat.PADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {09 07 11 0c 07 8e 69 5d 91 d7 11 05 11 0c 95 d7 6e 20 ff 00 00 00 6a 5f b8 0d } //01 00 
		$a_01_1 = {11 05 09 84 11 04 9e 11 06 11 07 02 11 07 91 11 05 11 05 08 84 95 11 05 09 84 95 d7 6e 20 ff 00 00 00 6a 5f b7 95 61 86 9c } //00 00 
	condition:
		any of ($a_*)
 
}