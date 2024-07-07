
rule Trojan_Win32_Cridex_LD_MTB{
	meta:
		description = "Trojan:Win32/Cridex.LD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b fb 2b f9 8d 44 38 90 01 01 2b f1 8d 5c 33 90 01 01 81 05 90 01 08 8b 35 90 01 04 8b 6c 24 10 89 75 90 01 01 8b f0 2b f1 83 c6 90 01 01 0f b7 f6 6a 90 01 01 5f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}