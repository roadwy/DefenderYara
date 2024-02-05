
rule Trojan_Win32_IStartSurf_DA_MTB{
	meta:
		description = "Trojan:Win32/IStartSurf.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 24 00 00 00 8b 3e ba c3 00 00 00 0f 45 d0 33 c0 8d 8f 90 01 04 3b fe 90 01 02 3b ce 90 01 02 8b 0e 30 14 01 40 3d 00 06 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}