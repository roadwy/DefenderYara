
rule Trojan_BAT_Redcap_PSSN_MTB{
	meta:
		description = "Trojan:BAT/Redcap.PSSN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 07 6f 3d 00 00 0a 0c 7e 1d 00 00 04 28 3e 00 00 0a 74 18 00 00 01 0d 09 13 04 11 04 72 85 02 00 70 6f 3f 00 00 0a 00 11 04 14 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}