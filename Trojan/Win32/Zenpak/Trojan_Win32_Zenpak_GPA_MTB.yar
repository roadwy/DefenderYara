
rule Trojan_Win32_Zenpak_GPA_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d7 01 f7 81 c7 ?? 00 00 00 8b 37 69 f8 ?? 00 00 00 01 fa 81 c2 ?? 00 00 00 0f b7 12 31 f2 01 ca 05 01 00 00 00 3d a9 01 00 00 89 d1 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}