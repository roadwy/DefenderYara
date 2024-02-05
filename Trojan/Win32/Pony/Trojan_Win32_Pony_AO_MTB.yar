
rule Trojan_Win32_Pony_AO_MTB{
	meta:
		description = "Trojan:Win32/Pony.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {32 01 1d dc ce 00 8a 89 da fa f1 2b c6 00 88 44 8a 00 3b 00 34 a1 83 bc 46 8b 82 f9 fc 8c 63 63 c5 b1 00 86 00 35 90 89 00 00 34 1b 1d 00 86 3a 00 7e } //00 00 
	condition:
		any of ($a_*)
 
}