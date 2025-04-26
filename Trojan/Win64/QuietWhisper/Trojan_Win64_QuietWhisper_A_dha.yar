
rule Trojan_Win64_QuietWhisper_A_dha{
	meta:
		description = "Trojan:Win64/QuietWhisper.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 74 6f 70 20 72 65 76 65 72 73 69 6e 67 20 74 68 65 20 62 69 6e 61 72 79 } //1 Stop reversing the binary
		$a_01_1 = {52 65 63 6f 6e 73 69 64 65 72 20 79 6f 75 72 20 6c 69 66 65 20 63 68 6f 69 63 65 73 } //1 Reconsider your life choices
		$a_01_2 = {41 6e 64 20 67 6f 20 74 6f 75 63 68 20 73 6f 6d 65 20 67 72 61 73 73 } //1 And go touch some grass
		$a_01_3 = {50 6f 46 78 50 72 6f 63 65 73 73 6f 72 4e 6f 74 69 66 69 63 61 74 69 6f 6e } //1 PoFxProcessorNotification
		$a_01_4 = {43 72 65 61 74 65 4c 6f 67 46 69 6c 65 } //1 CreateLogFile
		$a_01_5 = {41 64 64 4c 6f 67 43 6f 6e 74 61 69 6e 65 72 } //1 AddLogContainer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}