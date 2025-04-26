
rule Trojan_Win32_GoRat_DA_MTB{
	meta:
		description = "Trojan:Win32/GoRat.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //1 Go build ID:
		$a_01_1 = {53 70 61 72 6b 2f 63 6c 69 65 6e 74 2f 63 6f 72 65 2e 73 63 72 65 65 6e 73 68 6f 74 } //1 Spark/client/core.screenshot
		$a_01_2 = {53 70 61 72 6b 2f 63 6c 69 65 6e 74 2f 63 6f 72 65 2e 47 65 74 4d 61 63 41 64 64 72 65 73 73 } //1 Spark/client/core.GetMacAddress
		$a_01_3 = {53 70 61 72 6b 2f 63 6c 69 65 6e 74 2f 63 6f 72 65 2e 47 65 74 43 50 55 49 6e 66 6f } //1 Spark/client/core.GetCPUInfo
		$a_01_4 = {53 70 61 72 6b 2f 63 6c 69 65 6e 74 2f 63 6f 72 65 2e 47 65 74 52 41 4d 49 6e 66 6f } //1 Spark/client/core.GetRAMInfo
		$a_01_5 = {53 70 61 72 6b 2f 63 6c 69 65 6e 74 2f 63 6f 72 65 2e 6c 6f 63 6b } //1 Spark/client/core.lock
		$a_01_6 = {53 70 61 72 6b 2f 63 6c 69 65 6e 74 2f 63 6f 72 65 2e 6b 69 6c 6c 54 65 72 6d 69 6e 61 6c } //1 Spark/client/core.killTerminal
		$a_01_7 = {53 70 61 72 6b 2f 63 6c 69 65 6e 74 2f 63 6f 72 65 2e 75 70 6c 6f 61 64 46 69 6c 65 73 } //1 Spark/client/core.uploadFiles
		$a_01_8 = {53 70 61 72 6b 2f 63 6c 69 65 6e 74 2f 63 6f 72 65 2e 6b 69 6c 6c 50 72 6f 63 65 73 73 } //1 Spark/client/core.killProcess
		$a_01_9 = {53 70 61 72 6b 2f 63 6c 69 65 6e 74 2f 63 6f 72 65 2e 73 68 75 74 64 6f 77 6e } //1 Spark/client/core.shutdown
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}