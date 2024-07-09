
rule Trojan_BAT_CryptInject_RB_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {07 06 1a 58 4a 8f ?? ?? ?? ?? 0c 08 08 47 02 06 1a 58 4a 1f ?? 5d 91 61 d2 52 00 06 1a 58 06 1a 58 4a 17 d6 54 06 1e 58 06 1a 58 4a 06 4a fe ?? 16 fe ?? 52 06 1e 58 46 2d ?? 07 0d 2b } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}