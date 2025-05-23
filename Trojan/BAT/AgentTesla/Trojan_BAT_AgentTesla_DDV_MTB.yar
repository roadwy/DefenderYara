
rule Trojan_BAT_AgentTesla_DDV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {73 00 52 00 61 00 6b 00 45 00 31 00 36 00 68 00 41 00 36 00 56 00 } //1 sRakE16hA6V
		$a_01_1 = {2b 00 34 00 50 00 39 00 4e 00 63 00 78 00 4b 00 35 00 32 00 4d 00 } //1 +4P9NcxK52M
		$a_01_2 = {2b 00 66 00 75 00 75 00 44 00 72 00 58 00 73 00 70 00 52 00 38 00 } //1 +fuuDrXspR8
		$a_01_3 = {68 00 72 00 71 00 41 00 41 00 39 00 48 00 56 00 31 00 41 00 71 00 } //1 hrqAA9HV1Aq
		$a_01_4 = {2b 00 6a 00 46 00 31 00 47 00 6c 00 6d 00 55 00 39 00 59 00 51 00 } //1 +jF1GlmU9YQ
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_6 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_7 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_8 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_01_9 = {54 6f 49 6e 74 33 32 } //1 ToInt32
		$a_01_10 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 54 00 6f 00 74 00 61 00 6c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 53 00 79 00 73 00 74 00 65 00 6d 00 } //1 SELECT TotalPhysicalMemory FROM Win32_ComputerSystem
		$a_01_11 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 41 00 64 00 61 00 70 00 74 00 65 00 72 00 52 00 61 00 6d 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 56 00 69 00 64 00 65 00 6f 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 6c 00 65 00 72 00 } //1 SELECT AdapterRam FROM Win32_VideoController
		$a_01_12 = {47 65 74 45 6e 75 6d 65 72 61 74 6f 72 } //1 GetEnumerator
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}