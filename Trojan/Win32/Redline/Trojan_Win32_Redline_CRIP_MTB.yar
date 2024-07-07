
rule Trojan_Win32_Redline_CRIP_MTB{
	meta:
		description = "Trojan:Win32/Redline.CRIP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 20 0f b6 84 3c 90 01 04 88 84 0c 90 01 04 8a 44 24 1b 88 84 3c 90 01 04 0f b6 84 0c 90 01 04 03 44 24 90 01 01 0f b6 c0 0f b6 84 04 90 01 04 30 86 90 01 04 46 81 fe 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}