
rule Trojan_Win32_StealC_KYI_MTB{
	meta:
		description = "Trojan:Win32/StealC.KYI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 44 0c 3c 8b 4c 24 38 30 04 29 45 3b 6b 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}