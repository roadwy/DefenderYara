
rule Trojan_Win32_StealC_CCJN_MTB{
	meta:
		description = "Trojan:Win32/StealC.CCJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 50 6a 00 ff 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8b f0 33 c9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_StealC_CCJN_MTB_2{
	meta:
		description = "Trojan:Win32/StealC.CCJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c6 c1 e0 04 03 45 e8 8d 0c 33 33 c1 33 45 fc 89 45 d8 8b 45 d8 29 45 f8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}