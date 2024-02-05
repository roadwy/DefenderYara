
rule Trojan_Win32_SmokeLoader_GCW_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 90 01 01 03 45 90 01 01 8d 0c 3b 33 c1 31 45 90 01 01 2b 75 90 01 01 81 c3 90 01 04 ff 4d 90 01 01 c7 05 90 01 04 19 36 6b ff 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}