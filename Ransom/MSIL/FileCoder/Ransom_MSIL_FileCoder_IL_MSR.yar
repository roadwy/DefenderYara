
rule Ransom_MSIL_FileCoder_IL_MSR{
	meta:
		description = "Ransom:MSIL/FileCoder.IL!MSR,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 02 00 "
		
	strings :
		$a_80_0 = {45 6e 63 72 79 70 74 65 64 46 69 6c 65 73 } //EncryptedFiles  02 00 
		$a_80_1 = {46 69 72 73 74 52 61 6e 73 6f 6d 53 74 61 72 74 75 70 } //FirstRansomStartup  02 00 
		$a_80_2 = {2e 6c 69 6b 75 64 } //.likud  01 00 
		$a_80_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 49 4c 45 6c 65 63 74 69 6f 6e } //Software\Microsoft\Windows\CurrentVersion\Run\ILElection  02 00 
		$a_80_4 = {49 4c 45 6c 65 63 74 69 6f 6e 32 30 32 30 5f 52 61 6e 73 6f 6d 77 61 72 65 } //ILElection2020_Ransomware  00 00 
		$a_00_5 = {5d 04 00 00 f0 1a 04 } //80 5c 
	condition:
		any of ($a_*)
 
}