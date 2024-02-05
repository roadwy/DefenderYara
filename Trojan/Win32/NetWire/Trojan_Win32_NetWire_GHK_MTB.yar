
rule Trojan_Win32_NetWire_GHK_MTB{
	meta:
		description = "Trojan:Win32/NetWire.GHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b6 04 31 30 86 90 01 04 8b 45 f4 8d 88 90 01 04 b8 90 01 04 03 ce f7 e1 2b ca d1 e9 03 ca c1 e9 05 6b c1 26 b9 90 01 04 2b c8 0f b6 04 31 30 86 90 01 04 83 c6 90 01 01 81 fe 90 01 04 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}