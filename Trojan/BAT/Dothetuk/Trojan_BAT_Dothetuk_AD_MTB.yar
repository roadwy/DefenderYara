
rule Trojan_BAT_Dothetuk_AD_MTB{
	meta:
		description = "Trojan:BAT/Dothetuk.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 07 08 09 16 20 ff 00 00 00 6f ?? ?? ?? 0a b4 9c 08 17 d6 0c 08 20 db ff 00 00 31 e4 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}