
rule Trojan_Win32_LummaC_BT_MTB{
	meta:
		description = "Trojan:Win32/LummaC.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c1 8b 4d ?? 30 08 8b 45 ?? 8b 4d ?? 89 45 ?? 2b 45 ?? 89 4d ?? 3b c8 0f 82 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}