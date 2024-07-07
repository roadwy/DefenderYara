
rule Trojan_BAT_Xworm_KAE_MTB{
	meta:
		description = "Trojan:BAT/Xworm.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5f 63 13 04 08 11 04 60 d2 0c 07 11 05 25 20 01 00 00 00 58 13 05 08 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}