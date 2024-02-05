
rule Trojan_Win32_SmokeLoader_MPA_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.MPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 45 08 8b 45 e8 01 45 08 ff 75 08 8b c3 c1 e0 04 03 c6 33 45 0c 89 45 0c 8d 45 0c } //00 00 
	condition:
		any of ($a_*)
 
}