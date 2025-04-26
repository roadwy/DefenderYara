
rule Trojan_BAT_Reline_ABS_MTB{
	meta:
		description = "Trojan:BAT/Reline.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 d5 a2 2b 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 6e 00 00 00 76 00 00 00 fb 00 00 00 8a 01 00 00 f6 00 00 00 } //5
		$a_01_1 = {6f 54 63 4e 41 59 40 66 65 74 63 48 6a 68 4b 6f 47 74 65 63 52 } //1 oTcNAY@fetcHjhKoGtecR
		$a_01_2 = {74 63 4a 6d 6a 61 35 5b 74 63 4a 6d 56 61 4d } //1 tcJmja5[tcJmVaM
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_4 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_5 = {47 65 74 52 75 6e 74 69 6d 65 44 69 72 65 63 74 6f 72 79 } //1 GetRuntimeDirectory
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}