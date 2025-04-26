
rule Trojan_Win32_Bladabindi_RPU_MTB{
	meta:
		description = "Trojan:Win32/Bladabindi.RPU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 7d e0 03 4d 08 8a 11 01 c6 03 75 08 ff 4d ec 8a 06 88 16 88 01 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}