
rule Trojan_Win32_AveMaria_NECE_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.NECE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {b9 01 00 00 00 d1 e1 8b 95 6c ff ff ff 8a 44 05 f4 88 04 0a b9 01 00 00 00 6b d1 03 b8 01 00 00 00 6b c8 03 8b 85 6c ff ff ff 8a 54 15 f4 88 14 08 8b f4 ff 95 48 ff ff ff } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}