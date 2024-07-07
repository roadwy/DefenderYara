
rule Trojan_BAT_MassLogger_SA_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 48 49 5a 57 5a 54 4f 45 66 6b 4f 41 46 43 6e 4f 58 4b 6e 6b 4f 77 6a 75 6f 4c 55 2e 72 65 73 6f 75 72 63 65 73 } //1 wHIZWZTOEfkOAFCnOXKnkOwjuoLU.resources
		$a_01_1 = {73 63 53 56 4b 47 77 66 4b 4c 72 41 66 64 6d 4f 65 46 5a 4e 78 54 67 52 43 45 58 43 } //1 scSVKGwfKLrAfdmOeFZNxTgRCEXC
		$a_01_2 = {50 70 45 45 66 4f 42 57 4d 70 6a 6c 57 69 45 4b 68 45 77 49 62 57 6c 70 48 77 54 72 2e 72 65 73 6f 75 72 63 65 73 } //1 PpEEfOBWMpjlWiEKhEwIbWlpHwTr.resources
		$a_01_3 = {59 6c 41 41 77 6a 46 6b 51 64 78 63 4c 52 68 4d 75 67 48 53 4a 6f 71 46 4b 71 4b 76 } //1 YlAAwjFkQdxcLRhMugHSJoqFKqKv
		$a_01_4 = {4c 69 6d 65 5f 50 6f 6e 79 2e 65 78 65 } //1 Lime_Pony.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}