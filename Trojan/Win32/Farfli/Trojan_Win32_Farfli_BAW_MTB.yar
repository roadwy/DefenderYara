
rule Trojan_Win32_Farfli_BAW_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {83 ec 1c 8b 49 20 55 56 8d 44 24 14 57 50 51 ff 15 90 02 04 8b 4c 24 20 b8 56 55 55 55 f7 e9 8b c2 68 90 02 04 c1 e8 1f 03 d0 8b 44 24 28 8b fa 8d 4c 24 14 99 2b c2 90 00 } //02 00 
		$a_01_1 = {63 6c 6f 75 64 73 65 72 76 69 63 65 73 64 65 76 63 2e 74 6b 2f 70 69 63 74 75 72 65 73 73 2f 32 30 32 33 } //00 00 
	condition:
		any of ($a_*)
 
}