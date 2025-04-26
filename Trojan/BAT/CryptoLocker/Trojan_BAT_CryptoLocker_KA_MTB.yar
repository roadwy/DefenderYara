
rule Trojan_BAT_CryptoLocker_KA_MTB{
	meta:
		description = "Trojan:BAT/CryptoLocker.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 16 0b 2b 18 02 7b ?? 00 00 04 06 07 06 07 73 ?? ?? ?? ?? ?? ?? 00 00 0a 07 17 58 0b 07 04 fe 04 0c 08 2d e0 00 06 17 58 0a 06 03 fe 04 0d 09 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}