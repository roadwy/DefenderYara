
rule Trojan_BAT_Mimikatz_BA_MTB{
	meta:
		description = "Trojan:BAT/Mimikatz.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 16 73 ?? ?? ?? 0a 20 00 04 00 00 73 ?? ?? ?? 0a 0c 08 07 6f ?? ?? ?? 0a de 0a 08 2c 06 08 6f ?? ?? ?? 0a dc 07 6f ?? ?? ?? 0a 0d de 14 } //1
		$a_81_1 = {70 6f 77 65 72 73 68 65 6c 6c 5f 72 65 66 6c 65 63 74 69 76 65 5f 6d 69 6d 69 6b 61 74 7a } //1 powershell_reflective_mimikatz
		$a_81_2 = {4c 6f 61 64 4d 69 6d 69 42 79 43 6f 6d 6d 61 6e 64 } //1 LoadMimiByCommand
		$a_81_3 = {4d 69 6d 69 6b 61 74 7a 44 65 6c 65 67 61 74 65 } //1 MimikatzDelegate
		$a_81_4 = {4c 6f 61 64 4d 69 6d 69 } //1 LoadMimi
		$a_81_5 = {6d 69 6d 69 42 79 74 65 73 } //1 mimiBytes
		$a_81_6 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}