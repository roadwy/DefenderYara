
rule Trojan_BAT_Redline_GMZ_MTB{
	meta:
		description = "Trojan:BAT/Redline.GMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 08 02 8e 69 5d 1f 1f 59 1f 1f 58 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 1f 09 58 1f 11 58 1f 1a 59 91 61 28 ?? ?? ?? 0a 02 08 20 ?? ?? ?? ?? 58 20 ?? ?? ?? ?? 59 02 8e 69 5d 91 59 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}