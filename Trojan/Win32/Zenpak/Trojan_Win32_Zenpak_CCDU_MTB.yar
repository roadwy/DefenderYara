
rule Trojan_Win32_Zenpak_CCDU_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.CCDU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 00 8b 1b 0f b7 12 31 c2 89 34 24 89 5c 24 ?? 89 54 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}