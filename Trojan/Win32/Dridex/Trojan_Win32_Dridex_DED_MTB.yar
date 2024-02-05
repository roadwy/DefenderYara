
rule Trojan_Win32_Dridex_DED_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6b d0 59 8b 44 24 90 01 01 2b fe 05 90 01 04 89 44 24 90 01 01 a3 90 01 04 8d 8f 90 01 04 bf 90 01 04 03 ca 81 7c 24 90 01 05 8b 54 24 90 01 01 89 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}