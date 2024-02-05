
rule Trojan_Win32_Guloader_DEB_MTB{
	meta:
		description = "Trojan:Win32/Guloader.DEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {ac 48 6c 19 eb 04 ff 00 00 00 c3 3d 90 01 04 75 04 64 a7 f6 78 3d 90 09 0d 00 81 f2 90 01 04 3d 90 01 04 75 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}