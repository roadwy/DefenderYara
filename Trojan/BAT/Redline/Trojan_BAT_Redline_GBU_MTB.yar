
rule Trojan_BAT_Redline_GBU_MTB{
	meta:
		description = "Trojan:BAT/Redline.GBU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 63 11 62 6c 11 63 6c 28 ?? ?? ?? 0a 26 28 ?? ?? ?? 0a 26 28 ?? ?? ?? 0a 26 72 01 00 00 70 28 ?? ?? ?? 0a 26 11 07 07 03 07 91 09 61 d2 9c 1f 0a 13 64 1f 10 13 65 28 ?? ?? ?? 0a 26 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}