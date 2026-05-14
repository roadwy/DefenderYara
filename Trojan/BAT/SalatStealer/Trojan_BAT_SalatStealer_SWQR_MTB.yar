
rule Trojan_BAT_SalatStealer_SWQR_MTB{
	meta:
		description = "Trojan:BAT/SalatStealer.SWQR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 02 07 91 03 61 d2 9c 07 1f 0a 5d 2d 05 28 ?? ?? ?? 06 07 17 58 0b 07 02 8e 69 32 e2 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}