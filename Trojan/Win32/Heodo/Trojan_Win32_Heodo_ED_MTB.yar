
rule Trojan_Win32_Heodo_ED_MTB{
	meta:
		description = "Trojan:Win32/Heodo.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {83 c3 03 0f af 5d 10 03 f8 83 c0 04 0f af f8 8b 85 8c fd ff ff 03 de 2b c1 03 85 8c fd ff ff 8a d3 32 95 a3 fd ff ff } //00 00 
	condition:
		any of ($a_*)
 
}