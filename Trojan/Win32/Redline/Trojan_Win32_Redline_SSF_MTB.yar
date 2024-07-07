
rule Trojan_Win32_Redline_SSF_MTB{
	meta:
		description = "Trojan:Win32/Redline.SSF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 ce 89 4c 24 20 8b 4c 24 1c d3 ee 8b 4c 24 40 8d 44 24 14 c7 05 90 01 04 ee 3d ea f4 89 74 24 14 e8 c4 fe ff ff 8b 44 24 20 31 44 24 10 81 3d 90 01 04 e6 09 00 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}