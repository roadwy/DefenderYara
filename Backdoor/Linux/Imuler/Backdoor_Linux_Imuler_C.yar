
rule Backdoor_Linux_Imuler_C{
	meta:
		description = "Backdoor:Linux/Imuler.C,SIGNATURE_TYPE_MACHOHSTR_EXT,08 00 07 00 09 00 00 "
		
	strings :
		$a_01_0 = {2e 63 6f 6e 66 72 } //1 .confr
		$a_01_1 = {2f 74 6d 70 2f 2e 6d 64 } //1 /tmp/.md
		$a_01_2 = {2f 74 6d 70 2f 2e 6d 64 77 6f 72 6b 65 72 } //1 /tmp/.mdworker
		$a_01_3 = {2f 74 6d 70 2f 6c 61 75 6e 63 68 2d 49 4f 52 46 39 38 } //1 /tmp/launch-IORF98
		$a_01_4 = {46 69 6c 65 41 67 65 6e 74 41 70 70 } //1 FileAgentApp
		$a_01_5 = {61 70 70 6c 69 63 61 74 69 6f 6e 3a 6f 70 65 6e 54 65 6d 70 46 69 6c 65 3a } //1 application:openTempFile:
		$a_01_6 = {61 70 70 6c 69 63 61 74 69 6f 6e 3a 6f 70 65 6e 46 69 6c 65 57 69 74 68 6f 75 74 55 49 3a } //1 application:openFileWithoutUI:
		$a_01_7 = {61 70 70 6c 69 63 61 74 69 6f 6e 57 69 6c 6c 48 69 64 65 3a } //1 applicationWillHide:
		$a_01_8 = {54 4d 50 30 4d 33 34 } //1 TMP0M34
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=7
 
}