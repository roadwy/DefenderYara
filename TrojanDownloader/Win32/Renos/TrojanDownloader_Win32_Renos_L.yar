
rule TrojanDownloader_Win32_Renos_L{
	meta:
		description = "TrojanDownloader:Win32/Renos.L,SIGNATURE_TYPE_PEHSTR,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {25 70 72 6f 64 75 63 74 25 00 00 00 ff ff ff ff 08 00 00 00 25 75 70 64 61 74 65 25 00 00 00 00 ff ff ff ff 05 00 00 00 25 61 66 66 25 00 00 00 ff ff ff ff 04 00 00 00 25 6f 73 25 00 } //01 00 
		$a_01_1 = {6a 63 6c 2e 73 76 6e 2e 73 6f 75 72 63 65 66 6f 72 67 65 2e 6e 65 74 2f 73 76 6e 72 6f 6f 74 2f 6a 63 6c } //02 00 
		$a_01_2 = {43 6f 6e 74 69 6e 75 65 00 00 00 00 42 49 54 42 54 4e 31 5f 42 49 54 4d 41 50 00 } //00 00 
	condition:
		any of ($a_*)
 
}