
rule Trojan_Win32_Zenpack_MV_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {88 14 38 40 3b c1 72 90 01 01 90 18 a1 90 02 04 8b 0d 90 02 04 c1 e8 90 01 01 85 c0 76 13 56 57 8b f9 8b f0 e8 90 02 04 83 c7 08 4e 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}