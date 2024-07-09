
rule Trojan_Win32_Dridex_PC_MTB{
	meta:
		description = "Trojan:Win32/Dridex.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 08 5b 8b e5 5d c3 90 09 27 00 8b [0-05] 33 [0-05] c7 05 [0-08] 01 [0-05] a1 [0-04] 8b } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}