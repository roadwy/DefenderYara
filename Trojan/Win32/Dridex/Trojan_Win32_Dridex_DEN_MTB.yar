
rule Trojan_Win32_Dridex_DEN_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b d0 83 ef 5a 89 15 90 01 04 8b 54 24 10 2b ce 8b 44 24 0c 03 cf 05 90 01 04 89 44 24 0c 89 02 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}