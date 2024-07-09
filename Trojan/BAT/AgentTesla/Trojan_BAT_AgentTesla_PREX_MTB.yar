
rule Trojan_BAT_AgentTesla_PREX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PREX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //1 GetExportedTypes
		$a_81_1 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_81_2 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_81_3 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_81_4 = {24 61 30 66 62 31 38 36 65 2d 63 30 63 37 2d 34 31 35 36 2d 61 61 33 63 2d 65 32 63 64 64 32 34 39 34 39 62 61 } //1 $a0fb186e-c0c7-4156-aa3c-e2cdd24949ba
		$a_81_5 = {3a 2f 2f 66 69 6c 65 62 69 6e 2e 6e 65 74 2f 67 64 75 61 37 33 69 37 36 30 62 6a 37 7a 35 31 2f 4a 74 63 75 79 76 71 62 61 2e 64 61 74 } //1 ://filebin.net/gdua73i760bj7z51/Jtcuyvqba.dat
		$a_81_6 = {43 61 6e 63 65 6c 50 72 6f 64 75 63 65 72 } //1 CancelProducer
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
rule Trojan_BAT_AgentTesla_PREX_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.PREX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_81_0 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_81_1 = {48 74 74 70 43 6c 69 65 6e 74 } //1 HttpClient
		$a_81_2 = {47 65 74 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //1 GetByteArrayAsync
		$a_81_3 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_4 = {4d 65 74 68 6f 64 42 61 73 65 } //1 MethodBase
		$a_81_5 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_81_6 = {24 34 61 63 39 38 31 32 62 2d 63 38 62 32 2d 34 39 64 32 2d 62 61 63 32 2d 63 32 65 30 65 63 64 63 38 31 64 34 } //1 $4ac9812b-c8b2-49d2-bac2-c2e0ecdc81d4
		$a_03_7 = {3a 00 2f 00 2f 00 72 00 65 00 6d 00 69 00 73 00 61 00 74 00 2e 00 63 00 6f 00 6d 00 2e 00 75 00 79 00 2f 00 6e 00 6f 00 6e 00 2f 00 [0-14] 2e 00 70 00 64 00 66 00 } //1
		$a_03_8 = {3a 2f 2f 72 65 6d 69 73 61 74 2e 63 6f 6d 2e 75 79 2f 6e 6f 6e 2f [0-14] 2e 70 64 66 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_03_7  & 1)*1+(#a_03_8  & 1)*1) >=8
 
}