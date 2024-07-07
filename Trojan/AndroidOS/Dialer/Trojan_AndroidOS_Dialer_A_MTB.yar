
rule Trojan_AndroidOS_Dialer_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Dialer.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 6d 79 2f 6e 65 77 70 72 6f 6a 65 63 74 32 2f 53 6b 65 74 63 68 41 70 70 6c 69 63 61 74 69 6f 6e 3b } //2 Lcom/my/newproject2/SketchApplication;
		$a_02_1 = {74 65 6c 3a 2a 39 39 39 2a 90 02 02 2a 32 2a 90 01 05 2a 90 02 0e 2a 31 2a 90 01 01 25 32 33 23 90 00 } //1
		$a_00_2 = {69 6e 69 74 69 61 6c 69 7a 65 4c 6f 67 69 63 } //1 initializeLogic
		$a_00_3 = {44 65 62 75 67 41 63 74 69 76 69 74 79 2e 6a 61 76 61 } //1 DebugActivity.java
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}