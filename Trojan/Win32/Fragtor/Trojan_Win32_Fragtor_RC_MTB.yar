
rule Trojan_Win32_Fragtor_RC_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 69 6d 67 63 61 63 68 65 2e 63 6c 6f 75 64 73 65 72 76 69 63 65 73 64 65 76 63 2e 74 6b 2f 70 69 63 74 75 72 65 73 73 } //01 00  http://imgcache.cloudservicesdevc.tk/picturess
		$a_01_1 = {61 48 52 30 63 44 6f 76 4c 32 6c 74 5a 32 4e 68 59 32 68 6c 4c 6d 4e 73 62 33 56 6b 63 32 56 79 64 6d 6c 6a 5a 58 4e 6b 5a 58 5a 6a 4c 6e 52 72 4c 33 42 70 59 33 52 31 63 6d 56 7a 63 79 38 79 4d 44 49 7a 4c 77 3d 3d } //01 00  aHR0cDovL2ltZ2NhY2hlLmNsb3Vkc2VydmljZXNkZXZjLnRrL3BpY3R1cmVzcy8yMDIzLw==
		$a_01_2 = {52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00  RLDownloadToFileA
	condition:
		any of ($a_*)
 
}