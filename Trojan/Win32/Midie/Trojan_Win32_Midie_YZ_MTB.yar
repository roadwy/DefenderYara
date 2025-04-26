
rule Trojan_Win32_Midie_YZ_MTB{
	meta:
		description = "Trojan:Win32/Midie.YZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 54 24 13 8a 94 30 6c c9 43 00 2a d3 32 54 24 13 83 c0 01 3b c1 88 94 30 6b c9 43 00 7c e5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}