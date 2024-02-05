
rule Trojan_Win32_SmokeLoader_J_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b c2 d3 e8 8d 34 17 03 45 90 01 01 33 c6 31 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}