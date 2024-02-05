
rule Trojan_Win32_RedLine_RDAH_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {89 75 dc 3b f0 73 52 8b c6 83 e0 03 8a 88 90 01 04 32 0c 37 0f b6 1c 37 8d 04 19 88 04 37 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}