
rule Trojan_Win32_Dridex_DEO_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DEO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b cd 8b 7c 24 10 8b 44 24 18 83 44 24 10 04 05 90 01 04 a3 90 01 04 89 07 6b fa 1e 03 fd 83 6c 24 14 01 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}