
rule Trojan_Win32_Razy_CN_MTB{
	meta:
		description = "Trojan:Win32/Razy.CN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 37 81 c3 90 02 04 47 01 cb 29 d9 39 d7 75 d7 90 00 } //2
		$a_01_1 = {31 39 83 ec 04 89 14 24 5a 41 39 d9 75 e5 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}