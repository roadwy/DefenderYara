
rule Trojan_Win32_Cridex_PVK_MTB{
	meta:
		description = "Trojan:Win32/Cridex.PVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {ba 72 61 0b 00 8b ff c7 05 90 01 04 00 00 00 00 01 05 90 01 04 8b ff 8b 15 90 01 04 a1 90 01 04 89 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}