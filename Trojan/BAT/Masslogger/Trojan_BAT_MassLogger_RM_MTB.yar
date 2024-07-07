
rule Trojan_BAT_MassLogger_RM_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_01_0 = {6f 58 43 43 46 76 67 46 76 6f 4d 46 43 6e 66 64 74 59 45 77 64 4f 48 66 42 48 74 6e 41 2e 72 65 73 6f 75 72 63 65 73 } //1 oXCCFvgFvoMFCnfdtYEwdOHfBHtnA.resources
		$a_01_1 = {50 70 4c 59 7a 6b 67 66 61 59 42 6e 67 70 69 58 4d 55 65 52 4f 66 77 47 54 6e 7a 45 2e 72 65 73 6f 75 72 63 65 73 } //1 PpLYzkgfaYBngpiXMUeROfwGTnzE.resources
		$a_01_2 = {50 78 48 6d 71 66 77 55 6c 58 49 63 52 41 58 78 49 41 41 63 55 62 4d 63 4d 6b 47 6a 2e 72 65 73 6f 75 72 63 65 73 } //1 PxHmqfwUlXIcRAXxIAAcUbMcMkGj.resources
		$a_01_3 = {72 55 4b 50 69 64 4d 69 68 4a 69 79 51 48 65 64 53 6d 75 6d 4a 46 54 74 77 74 4b 74 41 2e 72 65 73 6f 75 72 63 65 73 } //1 rUKPidMihJiyQHedSmumJFTtwtKtA.resources
		$a_03_4 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 90 01 02 2e 50 72 6f 70 65 72 74 69 65 73 90 00 } //1
		$a_01_5 = {62 71 6f 63 56 59 54 52 4b 78 4b 4a 57 58 47 4c 59 67 6b 4b 4a 68 52 61 6e 63 62 4d 41 2e 72 65 73 6f 75 72 63 65 73 } //1 bqocVYTRKxKJWXGLYgkKJhRancbMA.resources
		$a_01_6 = {52 56 7a 79 77 48 42 62 68 68 65 63 63 52 4f 4a 72 53 66 52 6e 47 6a 7a 63 4a 6d 4e 2e 72 65 73 6f 75 72 63 65 73 } //1 RVzywHBbhheccROJrSfRnGjzcJmN.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=3
 
}