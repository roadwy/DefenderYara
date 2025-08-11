
rule Trojan_Win32_Antavmu_MR_MTB{
	meta:
		description = "Trojan:Win32/Antavmu.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 c9 31 d2 89 d0 89 d5 8b 9c 24 8c 00 00 00 83 e0 3f 83 c2 01 c1 fd 02 0f af c5 31 c8 83 c1 0d 01 d8 81 fa f4 01 } //10
		$a_01_1 = {89 d7 09 c7 85 f2 0f 95 44 24 03 85 ea 0f 95 c3 38 5c 24 03 0f 45 c7 01 d2 83 e9 01 } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=10
 
}