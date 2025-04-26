
rule Trojan_Win32_LummaC_RRX_MTB{
	meta:
		description = "Trojan:Win32/LummaC.RRX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 ff d6 8b 55 14 33 c0 85 ff 74 ?? 8b c8 83 e1 03 8a 4c 0d ?? 30 0c 06 40 3b c7 72 ?? ff 45 10 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}