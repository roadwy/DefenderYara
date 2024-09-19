
rule Trojan_Win32_Redline_AMAN_MTB{
	meta:
		description = "Trojan:Win32/Redline.AMAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 14 98 8b 44 24 ?? 8b 48 ?? 8b 44 24 ?? 8a 04 01 8b 4c 24 ?? 30 04 0a 8d 4c 24 ?? e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}