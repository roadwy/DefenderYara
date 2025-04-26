
rule Trojan_Win32_Olmasco_MA_MTB{
	meta:
		description = "Trojan:Win32/Olmasco.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 0f b6 4c 14 14 4b 8b da 86 e9 03 df 21 cb 8d 1c 10 83 eb 1a 30 2f 8d 5a 04 09 c3 b7 56 4b 47 b3 20 83 c3 7b 4d 0f 85 } //10
		$a_01_1 = {45 6a 6e 6b 78 6e 73 6f 6f 63 } //1 Ejnkxnsooc
		$a_01_2 = {55 71 6e 6a 71 63 61 79 63 6a } //1 Uqnjqcaycj
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}