
rule Trojan_Win32_SmokeLoader_B_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {d3 e8 03 c3 33 c2 31 45 fc 2b 75 fc 8b 45 d4 29 45 f8 ff 4d e8 0f 85 } //00 00 
	condition:
		any of ($a_*)
 
}