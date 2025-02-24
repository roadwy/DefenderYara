
rule Trojan_Win32_Zusy_AZUS_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AZUS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 68 04 00 00 80 6a 00 68 cb f9 1d 00 68 04 00 00 80 6a 00 68 d2 f9 1d 00 68 06 00 00 00 bb 90 5a 14 00 } //3
		$a_01_1 = {50 68 04 00 00 80 6a 00 68 d3 f7 1d 00 68 04 00 00 80 6a 00 68 dc f7 1d 00 68 06 00 00 00 bb 90 5a 14 00 } //2
		$a_01_2 = {50 68 04 00 00 80 6a 00 68 c6 f8 1d 00 68 04 00 00 80 6a 00 68 d0 f8 1d 00 68 06 00 00 00 bb 90 5a 14 00 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}