
rule Trojan_Win32_Vidar_PBK_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 c1 ce 08 2b ce 33 c6 f7 d3 c1 c2 11 33 c1 81 ef ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 33 c1 c1 ca 11 f7 d3 33 c6 03 ce c1 c6 08 49 33 c7 2b cc 81 f7 ?? ?? ?? ?? 46 f7 d1 c1 c7 13 4a 4a 87 c6 c1 c7 11 33 d9 49 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}