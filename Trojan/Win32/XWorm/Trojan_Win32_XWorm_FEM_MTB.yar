
rule Trojan_Win32_XWorm_FEM_MTB{
	meta:
		description = "Trojan:Win32/XWorm.FEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 c4 f0 b8 00 10 40 00 e8 01 00 00 00 9a 83 c4 10 8b e5 5d e9 43 c7 36 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}