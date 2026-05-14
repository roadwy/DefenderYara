
rule Trojan_Win64_LummaStealer_NL_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 0f 57 ff 4c 8b 35 48 31 9a 00 65 4d 8b 36 4d 8b 36 48 8b 04 24 48 8b 5c 24 50 48 01 d8 } //2
		$a_01_1 = {49 8b 4e 30 c6 81 e5 00 00 00 01 48 8b 0d 3d 69 90 00 48 83 39 00 0f 85 16 02 00 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_Win64_LummaStealer_NL_MTB_2{
	meta:
		description = "Trojan:Win64/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 29 8b 05 ?? ?? ?? ?? 65 48 8b 0c 25 ?? ?? ?? ?? 48 8b 04 c1 4c 8b 80 ?? ?? ?? ?? 48 8b 0d 46 b0 2e 00 31 d2 } //5
		$a_01_1 = {6d 61 6e 69 6e 74 65 72 6e 6d 65 6e 74 73 72 69 6a 69 62 6d 61 6e 69 6e 74 65 72 6e 6d 65 6e 74 } //1 maninternmentsrijibmaninternment
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_Win64_LummaStealer_NL_MTB_3{
	meta:
		description = "Trojan:Win64/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 72 69 74 65 72 66 75 6e 63 74 69 6f 6e 70 72 6f 2e 65 78 65 } //1 writerfunctionpro.exe
		$a_01_1 = {74 69 6d 65 70 72 6f 67 72 61 6d 6d 65 72 2e 65 78 65 } //1 timeprogrammer.exe
		$a_01_2 = {53 00 65 00 6e 00 64 00 45 00 66 00 66 00 65 00 63 00 74 00 69 00 76 00 65 00 6c 00 79 00 } //1 SendEffectively
		$a_01_3 = {44 65 63 72 79 70 74 46 69 6c 65 41 } //1 DecryptFileA
		$a_01_4 = {44 65 6c 4e 6f 64 65 52 75 6e 44 4c 4c 33 32 } //1 DelNodeRunDLL32
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_LummaStealer_NL_MTB_4{
	meta:
		description = "Trojan:Win64/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {48 89 11 49 89 d6 48 8b 62 38 48 89 fa 48 8b 3f ff d7 48 8b 0d 00 ff 40 00 65 48 8b 09 48 8b 01 48 8b 58 30 48 8b 83 90 00 00 00 } //2
		$a_01_1 = {45 0f 57 ff 4c 8b 35 0a 42 44 00 65 4d 8b 36 4d 8b 36 0f b6 44 24 1f 84 c0 74 12 } //1
		$a_01_2 = {57 72 69 74 65 5f 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 Write_ProcessMemory
		$a_01_3 = {56 69 72 74 75 61 6c 5f 41 6c 6c 6f 63 45 78 } //1 Virtual_AllocEx
		$a_01_4 = {47 65 74 52 65 6d 6f 74 65 50 65 62 41 64 64 72 } //1 GetRemotePebAddr
		$a_01_5 = {52 65 64 69 72 65 63 74 54 6f 50 61 79 6c 6f 61 64 } //1 RedirectToPayload
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}