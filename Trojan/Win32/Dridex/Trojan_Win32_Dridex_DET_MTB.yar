
rule Trojan_Win32_Dridex_DET_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6b ca 1b 03 cb 8b 44 24 10 2b d7 83 c2 b1 05 90 01 04 03 ca 89 44 24 10 8b 54 24 18 a3 90 01 04 89 02 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}