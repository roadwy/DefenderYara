
rule Trojan_Win32_Farfli_BAP_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 45 08 8a 08 32 4d 13 02 4d 13 88 08 40 89 45 08 b8 90 02 04 c3 ff 45 ec c7 45 fc 01 00 00 00 eb 90 00 } //01 00 
		$a_01_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 68 61 6e 6b 6a 69 6e 2e 74 65 6d 70 2e 25 64 } //01 00  C:\Windows\Temp\hankjin.temp.%d
		$a_01_2 = {55 50 4a 42 6f 77 6c 6a 6f 61 62 52 6f 44 69 6a 65 41 } //01 00  UPJBowljoabRoDijeA
		$a_01_3 = {5b 4e 61 67 65 42 6f 77 6c 5d } //01 00  [NageBowl]
		$a_01_4 = {5b 49 6c 73 65 70 72 5d } //00 00  [Ilsepr]
	condition:
		any of ($a_*)
 
}