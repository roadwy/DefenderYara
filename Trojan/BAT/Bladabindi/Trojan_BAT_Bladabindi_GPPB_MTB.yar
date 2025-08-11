
rule Trojan_BAT_Bladabindi_GPPB_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.GPPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_81_0 = {52 2f 2f 2f 65 2f 2f 2f 2f 2f 2f 2f 67 2f 41 2f 2f 2f 2f 2f 2f 73 2f 6d 2f 2e 2f 65 2f 2f 2f 2f 78 2f 2f 2f 2f 2f 65 } //1 R///e///////g/A//////s/m/./e////x/////e
	condition:
		((#a_81_0  & 1)*1) >=1
 
}