
rule Trojan_Win32_LummaC_AMC_MTB{
	meta:
		description = "Trojan:Win32/LummaC.AMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 cf 81 f7 e1 00 00 00 89 ca 81 f2 1e cd 22 95 81 c9 e1 32 dd 6a 21 d1 89 ca 83 e2 02 89 cb 83 cb 02 0f af da 01 fb 81 e1 fd 00 00 00 83 f2 02 0f af d1 01 da fe c2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}