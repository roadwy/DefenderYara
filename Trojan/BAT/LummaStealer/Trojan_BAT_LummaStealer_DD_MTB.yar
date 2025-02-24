
rule Trojan_BAT_LummaStealer_DD_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 06 08 91 58 07 08 91 58 20 00 01 00 00 5d 0d 06 09 91 13 04 06 09 06 08 91 9c 06 08 11 04 9c 08 17 58 0c 08 20 00 01 00 00 3f d1 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}