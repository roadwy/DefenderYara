
rule Trojan_Win32_Puppetzombie{
	meta:
		description = "Trojan:Win32/Puppetzombie,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {05 00 00 00 67 62 6a 73 6a 00 00 00 ff ff ff ff 05 00 00 00 63 71 6a 73 6a 00 00 00 ff ff ff ff 04 00 00 00 73 78 6a 73 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}