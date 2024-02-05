
rule Trojan_Win32_IcedId_DAZ_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 44 24 14 81 c1 90 01 04 8b f7 2b 35 90 01 04 83 c6 10 89 08 83 c0 04 83 6c 24 18 01 89 44 24 14 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}