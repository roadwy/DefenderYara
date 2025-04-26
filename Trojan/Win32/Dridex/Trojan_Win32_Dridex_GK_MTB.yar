
rule Trojan_Win32_Dridex_GK_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GK!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {40 6f 66 6b 69 77 65 72 65 7a 34 } //1 @ofkiwerez4
		$a_01_1 = {66 72 65 71 75 65 6e 74 6f 6e 63 6f 64 65 76 66 } //1 frequentoncodevf
		$a_01_2 = {57 59 6f 76 75 6c 6e 65 72 61 62 69 6c 69 74 69 65 73 38 53 } //1 WYovulnerabilities8S
		$a_01_3 = {54 68 69 73 62 31 32 74 68 65 61 64 64 72 65 73 73 61 63 63 6f 72 64 69 6e 67 41 6c 74 65 72 6e 61 74 69 76 65 6c 79 2c 74 6f } //1 Thisb12theaddressaccordingAlternatively,to
		$a_01_4 = {35 4b 47 6f 6f 67 6c 65 32 73 36 6a 5a 43 6d } //1 5KGoogle2s6jZCm
		$a_01_5 = {70 72 6f 63 65 73 73 65 73 32 77 48 74 68 65 42 61 64 67 65 72 } //1 processes2wHtheBadger
		$a_01_6 = {47 65 74 54 65 78 74 45 78 74 65 6e 74 45 78 50 6f 69 6e 74 49 } //1 GetTextExtentExPointI
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}