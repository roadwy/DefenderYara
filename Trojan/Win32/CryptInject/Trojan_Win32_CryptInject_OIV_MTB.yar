
rule Trojan_Win32_CryptInject_OIV_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.OIV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f8 83 c1 01 33 4d fc 2b c1 8b 55 f8 88 82 ?? ?? ?? ?? eb 18 8b 45 f4 0f be 08 51 e8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}