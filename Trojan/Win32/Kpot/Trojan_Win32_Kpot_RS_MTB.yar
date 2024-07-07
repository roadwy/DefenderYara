
rule Trojan_Win32_Kpot_RS_MTB{
	meta:
		description = "Trojan:Win32/Kpot.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_00_0 = {83 c0 7b 89 04 24 b8 f9 cd 03 00 01 04 24 83 2c 24 7b 8b 04 24 8a 04 10 88 04 11 } //1
		$a_02_1 = {c1 e9 05 03 d7 33 c2 03 ce 81 3d 90 01 04 72 07 00 00 c7 05 90 01 04 b4 1a 3a df 90 00 } //1
		$a_02_2 = {c1 e9 05 03 d3 33 c2 03 ce 81 3d 90 01 04 72 07 00 00 c7 05 90 01 04 b4 1a 3a df 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}