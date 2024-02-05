
rule Trojan_Win32_Cridex_VD_MTB{
	meta:
		description = "Trojan:Win32/Cridex.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {64 89 10 e9 90 02 0d b8 90 01 04 50 e8 90 01 04 b8 90 01 04 31 c9 80 34 01 90 01 01 41 81 f9 90 01 04 75 90 01 01 05 90 01 04 ff e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}