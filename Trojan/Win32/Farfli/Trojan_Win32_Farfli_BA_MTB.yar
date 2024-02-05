
rule Trojan_Win32_Farfli_BA_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 51 8b 1b 8b 03 83 c3 04 89 07 83 c7 04 53 8b 1b 81 c3 08 00 00 00 b9 00 01 00 00 8b f3 f3 a4 5b 83 c3 04 59 5b 83 c3 04 49 0f } //01 00 
		$a_01_1 = {73 6a 61 6b 6c 65 6a 34 69 6a 61 6c 6b 62 6e 6c 6b 73 6a 6c 6b 73 6a 6b 67 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}