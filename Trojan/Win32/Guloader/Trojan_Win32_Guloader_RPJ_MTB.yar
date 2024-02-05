
rule Trojan_Win32_Guloader_RPJ_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f ae f0 ff 31 90 02 10 5d 90 02 10 81 f5 90 02 10 55 90 02 10 59 90 02 10 89 0c 37 90 02 10 4e 90 02 10 4e 90 02 10 4e 90 02 10 4e 7d 90 02 10 89 f9 90 02 10 51 90 02 10 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}