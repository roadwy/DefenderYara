
rule Trojan_Win32_StealC_ERR_MTB{
	meta:
		description = "Trojan:Win32/StealC.ERR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d8 8b 45 a4 05 ee cc 00 00 2b 45 9c 03 d8 6a 00 e8 90 01 04 2b d8 8b 45 d4 31 18 83 45 ec 04 6a 00 e8 90 01 04 83 c0 04 01 45 d4 8b 45 ec 3b 45 d0 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}