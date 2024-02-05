
rule Trojan_Win32_SmokeLoader_RPF_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f be d3 8d 76 01 80 eb 41 8b c2 83 c8 20 80 fb 19 8a 5e ff 0f 47 c2 33 c7 69 f8 93 01 00 01 84 db 75 dd } //00 00 
	condition:
		any of ($a_*)
 
}