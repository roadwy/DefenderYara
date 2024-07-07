
rule Trojan_Win32_VirLock_RPV_MTB{
	meta:
		description = "Trojan:Win32/VirLock.RPV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {8a 06 32 c2 90 88 07 90 46 90 e9 } //10
		$a_01_1 = {47 49 90 83 f9 00 0f 85 } //5
		$a_01_2 = {8a 06 32 c2 88 07 90 e9 } //10
		$a_01_3 = {46 47 90 49 83 f9 00 90 0f 85 } //5
		$a_01_4 = {8a 06 32 c2 e9 } //10
		$a_01_5 = {88 07 46 47 49 83 f9 00 0f 85 } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*10+(#a_01_3  & 1)*5+(#a_01_4  & 1)*10+(#a_01_5  & 1)*5) >=15
 
}