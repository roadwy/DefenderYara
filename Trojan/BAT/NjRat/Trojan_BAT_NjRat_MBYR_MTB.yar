
rule Trojan_BAT_NjRat_MBYR_MTB{
	meta:
		description = "Trojan:BAT/NjRat.MBYR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {54 56 71 51 2a 2a 2d 2a 2a 2a 2a 2d 2a 2a 4d 2a 2a 2d 2a 2a 2a 2a 2d 2a 2a 2a 2a 2d 2a 2a 2a 2a 2d 2a 2a 45 2a 2a 2d 2a 2a 2a 2a 2d 2a 2a 2a 2a 2d 2a 2a 2a 2a 2d 2a 2a 2f 2f 38 } //1 TVqQ**-****-**M**-****-****-****-**E**-****-****-****-**//8
	condition:
		((#a_01_0  & 1)*1) >=1
 
}