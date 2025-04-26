
rule Ransom_Win32_SmertRansom_MX_MTB{
	meta:
		description = "Ransom:Win32/SmertRansom.MX!MTB,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 73 6d 65 72 74 } //10 .smert
		$a_01_1 = {73 6d 65 72 74 2e 65 78 65 } //10 smert.exe
		$a_01_2 = {63 72 79 70 74 73 76 63 } //1 cryptsvc
		$a_01_3 = {77 75 61 75 73 65 72 76 } //1 wuauserv
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}