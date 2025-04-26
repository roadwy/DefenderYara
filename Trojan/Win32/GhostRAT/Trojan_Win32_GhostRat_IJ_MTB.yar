
rule Trojan_Win32_GhostRat_IJ_MTB{
	meta:
		description = "Trojan:Win32/GhostRat.IJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c7 01 9e 68 10 00 00 c7 40 0c 00 00 00 00 c7 40 10 00 00 00 00 89 58 04 c7 00 01 00 00 00 89 70 08 c1 f8 0c 8d 96 80 10 00 00 89 f1 50 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}