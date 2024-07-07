
rule Trojan_Win32_Hancitor_LLQ_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.LLQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 39 0f b7 ca 89 4c 24 90 02 02 8b 4c 24 90 02 02 8d 04 41 8b 4c 24 90 02 02 81 c1 90 01 04 03 c8 83 3d 90 01 05 74 90 01 01 0f af 0d 90 01 04 2b 4c 24 90 01 01 90 18 83 c1 1e 0f b7 c2 2b c6 81 c7 cc 4a 06 01 03 c1 89 3d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}