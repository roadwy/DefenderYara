
rule Trojan_Win32_FlyStudio_DY_MTB{
	meta:
		description = "Trojan:Win32/FlyStudio.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b ec 68 02 00 00 80 6a 00 68 00 00 00 00 6a 00 6a 00 6a 00 68 01 00 01 00 68 03 00 01 06 68 04 00 01 52 68 03 00 00 00 bb } //2
		$a_01_1 = {6a 08 68 76 5d 01 16 68 04 00 01 52 e8 } //1
		$a_01_2 = {35 31 31 34 2e 64 6c 6c 00 5f c6 f4 b6 af d7 d3 b3 cc d0 f2 } //1
		$a_01_3 = {35 31 31 2e 64 6c 6c 00 5f c6 f4 b6 af d7 d3 b3 cc d0 f2 } //1
		$a_01_4 = {54 50 30 30 30 30 2e 64 6c 6c 00 5f c6 f4 b6 af d7 d3 b3 cc d0 f2 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}