
rule Trojan_Win32_Redline_MRA_MTB{
	meta:
		description = "Trojan:Win32/Redline.MRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 3c 90 01 01 03 c6 59 59 8b 4c 24 90 01 01 0f b6 c0 8a 44 04 90 01 01 30 04 29 45 3b ac 24 90 01 04 7c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}