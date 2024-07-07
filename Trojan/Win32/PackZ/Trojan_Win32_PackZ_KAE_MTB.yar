
rule Trojan_Win32_PackZ_KAE_MTB{
	meta:
		description = "Trojan:Win32/PackZ.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 cb 81 eb 90 01 04 8b 32 bf 90 01 04 81 c1 90 01 04 81 e6 90 01 04 81 c7 90 01 04 bf 90 01 04 89 cf 31 30 09 ff 49 40 41 f7 d1 4b 81 c2 90 01 04 21 cf f7 d7 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}