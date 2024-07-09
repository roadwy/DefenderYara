
rule Trojan_Win32_Manuscrypt_RF_MTB{
	meta:
		description = "Trojan:Win32/Manuscrypt.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 6d 00 2f 00 bb 78 00 7a 00 be 6d 00 65 00 [0-60] c7 44 24 ?? 78 00 76 00 c7 44 24 ?? 2e 00 79 00 89 7c 24 ?? 89 54 24 ?? 89 4c 24 ?? c7 44 24 ?? 25 00 64 00 c7 44 24 ?? 2e 00 68 00 c7 44 24 ?? 74 00 6d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}