
rule TrojanSpy_BAT_AgentTesla_AQ_MTB{
	meta:
		description = "TrojanSpy:BAT/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_01_0 = {4d 75 6c 74 69 63 61 73 74 44 65 6c 65 67 61 74 65 } //1 MulticastDelegate
		$a_01_1 = {53 74 72 65 61 6d 57 72 69 74 65 72 } //1 StreamWriter
		$a_01_2 = {54 65 78 74 57 72 69 74 65 72 } //1 TextWriter
		$a_01_3 = {43 72 65 61 74 65 54 65 78 74 } //1 CreateText
		$a_01_4 = {57 72 69 74 65 4c 69 6e 65 } //1 WriteLine
		$a_01_5 = {46 6c 75 73 68 } //1 Flush
		$a_01_6 = {43 6f 6d 62 69 6e 65 } //1 Combine
		$a_01_7 = {53 74 6f 70 77 61 74 63 68 } //1 Stopwatch
		$a_01_8 = {53 6c 65 65 70 } //1 Sleep
		$a_01_9 = {42 69 74 43 6f 6e 76 65 72 74 65 72 } //1 BitConverter
		$a_01_10 = {41 73 79 6e 63 43 61 6c 6c 62 61 63 6b } //1 AsyncCallback
		$a_01_11 = {42 69 6e 61 72 79 53 65 61 72 63 68 } //1 BinarySearch
		$a_01_12 = {56 69 64 65 6f 4c 41 4e } //1 VideoLAN
		$a_00_13 = {6c 00 6f 00 67 00 2e 00 74 00 78 00 74 00 } //1 log.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_00_13  & 1)*1) >=14
 
}