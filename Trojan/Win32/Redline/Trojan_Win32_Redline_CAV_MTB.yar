
rule Trojan_Win32_Redline_CAV_MTB{
	meta:
		description = "Trojan:Win32/Redline.CAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 4d d3 51 8d 4d e4 e8 [0-04] 0f b6 10 6b d2 ?? 8b 45 08 03 45 d4 0f b6 08 33 ca 8b 55 08 03 55 d4 88 0a e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}