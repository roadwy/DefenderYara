
rule Trojan_Win32_Redline_AMAD_MTB{
	meta:
		description = "Trojan:Win32/Redline.AMAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 14 ?? 03 44 24 ?? 0f b6 c0 8a 44 04 ?? 30 04 0e 46 3b f5 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}