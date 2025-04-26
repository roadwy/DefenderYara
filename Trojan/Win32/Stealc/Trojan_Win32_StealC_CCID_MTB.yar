
rule Trojan_Win32_StealC_CCID_MTB{
	meta:
		description = "Trojan:Win32/StealC.CCID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 8d 4d ?? 8b 55 ?? 33 45 ?? 33 d0 89 55 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}