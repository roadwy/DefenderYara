
rule Trojan_Win32_Injuke_GAC_MTB{
	meta:
		description = "Trojan:Win32/Injuke.GAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {2a 01 00 00 00 27 bf 90 01 06 00 da 0a 00 73 90 01 01 0d ca 70 e0 78 00 00 d4 00 00 5d 58 90 00 } //10
		$a_03_1 = {2a 01 00 00 00 bf 90 01 04 17 81 00 00 da 0a 00 73 90 01 01 0d ca 90 01 03 00 00 d4 00 00 34 fc 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}