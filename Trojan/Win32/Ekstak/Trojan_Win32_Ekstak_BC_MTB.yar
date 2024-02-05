
rule Trojan_Win32_Ekstak_BC_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 f0 03 c1 42 8a 1c 0e 8b 75 0c 88 1c 30 8a 81 90 01 04 84 c0 75 90 01 01 a1 90 01 04 8a 1d 90 01 04 03 c1 03 c6 30 18 83 3d 90 01 04 03 76 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}