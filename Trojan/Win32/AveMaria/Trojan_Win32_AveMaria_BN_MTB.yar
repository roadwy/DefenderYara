
rule Trojan_Win32_AveMaria_BN_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e2 05 0b ca 0f b6 85 [0-04] 33 c8 8b 55 dc 03 55 f8 88 0a 8b 45 e8 83 c0 01 99 b9 0c 00 00 00 f7 f9 89 55 e8 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}