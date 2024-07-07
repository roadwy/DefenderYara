
rule Trojan_Win32_Zenpak_GM_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 d3 03 c2 90 02 30 8b 85 90 01 04 40 83 c4 90 01 01 89 85 90 01 04 0f b6 94 15 90 02 20 30 50 90 01 01 83 7d 90 02 20 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}