
rule Trojan_Win32_Amadey_BKC_MTB{
	meta:
		description = "Trojan:Win32/Amadey.BKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 37 8d 4d c4 32 06 88 45 ?? 8d 45 ef 6a 01 50 c7 45 d4 ?? ?? ?? ?? c7 45 d8 0f 00 00 00 c6 45 c4 00 e8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}