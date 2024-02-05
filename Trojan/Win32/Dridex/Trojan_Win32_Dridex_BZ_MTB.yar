
rule Trojan_Win32_Dridex_BZ_MTB{
	meta:
		description = "Trojan:Win32/Dridex.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 e9 2d ad 00 00 89 0d 90 01 04 8b 15 90 01 04 03 95 90 01 04 03 15 90 01 04 89 15 90 01 04 a1 90 01 04 2b 05 90 01 04 a3 90 01 04 b9 01 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}