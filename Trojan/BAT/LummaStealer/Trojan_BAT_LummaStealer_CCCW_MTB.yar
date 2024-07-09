
rule Trojan_BAT_LummaStealer_CCCW_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.CCCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 06 07 93 1f 3c 28 ?? ?? ?? ?? 61 02 61 d1 9d 38 ?? ?? ?? ?? 1e 28 ?? ?? ?? ?? 0c 2b b6 06 8e 69 0b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}