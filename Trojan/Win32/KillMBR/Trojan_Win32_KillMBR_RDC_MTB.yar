
rule Trojan_Win32_KillMBR_RDC_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 8b f0 8d 45 fc 50 68 00 80 00 00 68 90 01 04 56 ff d3 56 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}