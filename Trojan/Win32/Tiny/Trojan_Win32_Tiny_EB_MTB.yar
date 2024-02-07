
rule Trojan_Win32_Tiny_EB_MTB{
	meta:
		description = "Trojan:Win32/Tiny.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {6c 74 69 61 70 6d 79 7a 6d 6a 78 72 76 72 74 73 2e 69 6e 66 6f } //01 00  ltiapmyzmjxrvrts.info
		$a_81_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_81_2 = {25 25 74 65 6d 70 25 25 5c 25 73 2e 65 78 65 } //01 00  %%temp%%\%s.exe
		$a_81_3 = {68 74 74 70 3a 2f 2f 25 73 2e 25 73 2f 76 34 2f 25 73 2e 65 78 65 } //00 00  http://%s.%s/v4/%s.exe
	condition:
		any of ($a_*)
 
}