
rule Trojan_Win32_Zenload_RH_MTB{
	meta:
		description = "Trojan:Win32/Zenload.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 73 70 72 65 61 64 2e 65 78 65 00 00 63 6d 64 20 2f 63 20 63 73 63 72 69 70 74 20 63 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 76 62 73 2e 76 62 73 } //00 00 
	condition:
		any of ($a_*)
 
}