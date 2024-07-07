
rule Trojan_Win32_Redline_GBC_MTB{
	meta:
		description = "Trojan:Win32/Redline.GBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c8 c7 05 90 01 04 81 00 00 00 81 e1 90 01 04 79 08 49 81 c9 90 01 04 41 8a 84 0d 90 01 04 8b 9d 90 01 04 8b 8d 90 01 04 30 04 19 eb 06 8b 9d 90 01 04 43 3b 9d 90 01 04 89 9d 90 01 04 bb 02 00 00 00 0f 82 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}