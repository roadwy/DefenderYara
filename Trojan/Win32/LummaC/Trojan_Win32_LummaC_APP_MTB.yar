
rule Trojan_Win32_LummaC_APP_MTB{
	meta:
		description = "Trojan:Win32/LummaC.APP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 c3 0f b6 cb 0f b6 94 0d ?? fe ff ff 88 94 3d ?? fe ff ff 88 84 0d ?? fe ff ff 02 84 3d ?? fe ff ff 0f b6 c0 0f b6 84 05 ?? fe ff ff 8b 4d 08 8b 55 d4 30 04 11 89 d1 41 3b 4d 0c 0f 84 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}