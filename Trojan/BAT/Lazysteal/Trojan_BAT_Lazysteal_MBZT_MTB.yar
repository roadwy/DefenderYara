
rule Trojan_BAT_Lazysteal_MBZT_MTB{
	meta:
		description = "Trojan:BAT/Lazysteal.MBZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 94 58 20 00 01 00 00 5d 94 0a 02 07 02 07 91 06 28 90 01 03 0a 61 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}