
rule Trojan_Win32_Dridex_BKY_MTB{
	meta:
		description = "Trojan:Win32/Dridex.BKY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 02 83 05 90 01 05 83 05 90 01 05 a1 90 01 04 3b 05 90 01 04 0f 82 90 09 24 00 a1 90 01 04 8b 15 90 01 04 01 10 a1 90 01 04 03 05 90 01 04 03 05 90 01 04 8b 15 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}