
rule TrojanDropper_O97M_Donoff_STE_MTB{
	meta:
		description = "TrojanDropper:O97M/Donoff.STE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 20 68 74 74 70 3a 2f 2f 64 6f 63 75 6d 65 6e 74 73 2e 70 72 6f 2e 62 72 2f 22 } //1 = " http://documents.pro.br/"
		$a_01_1 = {47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 22 29 2e 47 65 74 28 22 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 2e 43 72 65 61 74 65 20 4d 69 63 72 6f 73 6f 66 74 43 44 54 32 30 32 32 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 70 69 64 } //1 GetObject("winmgmts:").Get("Win32_Process").Create MicrosoftCDT2022, Null, Null, pid
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDropper_O97M_Donoff_STE_MTB_2{
	meta:
		description = "TrojanDropper:O97M/Donoff.STE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 4f 56 75 72 65 2e 4f 70 65 6e 20 28 4d 49 41 69 4e 20 2b 20 22 5c 53 62 59 4b 4f 2e 6a 73 22 29 } //1 FOVure.Open (MIAiN + "\SbYKO.js")
		$a_03_1 = {49 66 20 44 69 72 28 4d 49 41 69 4e 20 2b 20 22 5c 53 62 59 4b 4f 2e 74 78 74 22 29 20 3d 20 22 22 20 54 68 65 6e [0-03] 41 70 70 6c 69 63 61 74 69 6f 6e 2e 57 61 69 74 20 28 4e 6f 77 20 2b 20 54 69 6d 65 56 61 6c 75 65 28 22 [0-0f] 22 29 29 } //1
		$a_01_2 = {46 4f 56 75 72 65 2e 4e 61 6d 65 73 70 61 63 65 28 4d 49 41 69 4e 29 2e 53 65 6c 66 2e 49 6e 76 6f 6b 65 56 65 72 62 20 22 50 61 73 74 65 22 } //1 FOVure.Namespace(MIAiN).Self.InvokeVerb "Paste"
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDropper_O97M_Donoff_STE_MTB_3{
	meta:
		description = "TrojanDropper:O97M/Donoff.STE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 22 20 26 20 22 6d 67 6d 22 20 26 20 22 74 73 22 20 26 20 22 3a 77 22 20 26 20 22 69 6e 22 20 26 20 22 33 32 5f 22 20 26 20 22 70 72 22 20 26 20 22 6f 63 22 20 26 20 22 65 73 22 20 26 20 22 73 22 29 } //1 GetObject("win" & "mgm" & "ts" & ":w" & "in" & "32_" & "pr" & "oc" & "es" & "s")
		$a_01_1 = {22 68 22 20 26 20 22 74 74 70 22 20 26 20 22 3a 2f 2f 22 20 26 20 22 61 73 22 20 26 20 22 65 6e 22 20 26 20 22 61 6c 22 20 26 20 22 2e 6d 22 20 26 20 22 65 64 69 22 20 26 20 22 61 6e 65 77 22 20 26 20 22 73 6f 6e 6c 22 20 26 20 22 69 6e 65 22 20 26 20 22 2e 63 22 20 26 20 22 6f 6d 2f 22 20 26 20 22 67 6f 22 20 26 20 22 6f 64 2f 22 20 26 20 22 6c 75 63 22 20 26 20 22 6b 2f 22 20 26 20 22 66 6c 22 20 26 20 22 61 76 22 20 26 20 22 6f 72 2f 22 20 26 20 22 6c 69 73 22 20 26 20 22 74 2e 22 20 26 20 22 70 68 22 20 26 20 22 70 } //1 "h" & "ttp" & "://" & "as" & "en" & "al" & ".m" & "edi" & "anew" & "sonl" & "ine" & ".c" & "om/" & "go" & "od/" & "luc" & "k/" & "fl" & "av" & "or/" & "lis" & "t." & "ph" & "p
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}