
rule Trojan_Win32_Rhadamanthys_ILM_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.ILM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 ea 89 54 24 14 8b 44 24 38 01 44 24 14 8b 44 24 24 31 44 24 90 01 01 81 3d 90 01 08 75 90 01 01 57 57 57 ff 15 90 01 04 8b 44 24 10 33 44 24 90 01 01 89 44 24 10 2b f0 8d 44 24 90 01 01 e8 90 01 04 83 6c 24 90 01 02 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}