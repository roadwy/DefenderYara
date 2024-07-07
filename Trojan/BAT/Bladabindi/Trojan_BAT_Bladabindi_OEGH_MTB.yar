
rule Trojan_BAT_Bladabindi_OEGH_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.OEGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_81_0 = {6b 65 72 6e 65 6c 33 32 } //1 kernel32
		$a_81_1 = {57 72 69 74 65 42 79 74 65 } //1 WriteByte
		$a_81_2 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
		$a_81_4 = {43 6f 6d 70 61 72 65 53 74 72 69 6e 67 } //1 CompareString
		$a_81_5 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_81_6 = {4f 76 65 72 66 6c 6f 77 45 78 63 65 70 74 69 6f 6e } //1 OverflowException
		$a_81_7 = {53 74 72 65 61 6d 57 72 69 74 65 72 } //1 StreamWriter
		$a_81_8 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_81_9 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
		$a_81_10 = {52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 } //1 RtlMoveMemory
		$a_81_11 = {68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 } //1 https://cdn.discordapp.com/attachment
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=12
 
}