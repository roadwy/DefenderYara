
rule Trojan_Win32_Bsymem_AO_MTB{
	meta:
		description = "Trojan:Win32/Bsymem.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e8 8b 55 ec 01 02 8b 45 b8 03 45 e8 89 45 b4 8b 45 d8 03 45 b4 8b 55 ec 31 02 6a 00 e8 [0-04] 8b d8 8b 45 e8 83 c0 04 03 d8 6a 00 e8 [0-04] 2b d8 6a 00 e8 [0-04] 03 d8 6a 00 e8 [0-04] 2b d8 89 5d e8 8b 45 ec 83 c0 04 89 45 ec 8b 45 e8 3b 45 e4 72 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}