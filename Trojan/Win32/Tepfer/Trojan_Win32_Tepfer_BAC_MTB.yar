
rule Trojan_Win32_Tepfer_BAC_MTB{
	meta:
		description = "Trojan:Win32/Tepfer.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {5a 2b d0 31 13 6a 00 e8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Tepfer_BAC_MTB_2{
	meta:
		description = "Trojan:Win32/Tepfer.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {5a 2b d0 31 13 83 45 ec 04 6a 00 e8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}