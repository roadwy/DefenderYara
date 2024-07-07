
rule Trojan_Win32_Zenpak_GZM_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 ea 05 29 c2 90 01 02 4a ba 90 01 04 4a 89 f8 50 8f 05 90 01 04 e8 90 01 04 c3 4a 01 1d 90 01 04 8d 05 90 01 04 89 30 8d 05 90 01 04 89 28 90 00 } //10
		$a_03_1 = {29 c2 89 e0 50 8f 05 90 01 04 83 f0 01 e8 90 01 04 01 2d 90 01 04 89 c2 8d 05 90 01 04 01 18 e8 90 01 04 c3 01 c2 8d 05 90 01 04 01 38 8d 05 90 01 04 89 30 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}