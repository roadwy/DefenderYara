
rule Trojan_Win32_Dridex_NT_MTB{
	meta:
		description = "Trojan:Win32/Dridex.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d2 8b d2 a1 90 02 06 89 90 02 05 31 90 02 05 c7 05 90 02 08 8b 90 02 05 01 90 02 05 a1 90 02 04 8b 90 02 05 89 08 8b e5 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}