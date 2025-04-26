
rule Trojan_Win32_LummaC_CCJG_MTB{
	meta:
		description = "Trojan:Win32/LummaC.CCJG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 45 fc 0f b6 08 8b 15 ?? ?? ?? ?? 81 c2 96 00 00 00 33 ca 8b 45 08 03 45 fc 88 08 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}