
rule Trojan_Win32_Dridex_LBL_MTB{
	meta:
		description = "Trojan:Win32/Dridex.LBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {d3 c0 8a fc 8a e6 d3 cb ff 4d 90 01 01 75 90 01 01 89 4d 90 01 01 2b 4d 90 01 01 31 d9 83 e0 00 09 c8 8b 4d 90 01 01 81 e1 90 02 04 8b 0c e4 83 ec 90 01 01 aa 49 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}