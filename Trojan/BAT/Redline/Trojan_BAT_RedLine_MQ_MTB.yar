
rule Trojan_BAT_RedLine_MQ_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {57 fd a2 35 09 00 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 39 00 00 00 28 00 00 00 6c 00 00 00 65 00 00 00 3d } //10
		$a_01_1 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_2 = {53 6c 65 65 70 } //1 Sleep
		$a_01_3 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //1 QueryPerformanceCounter
		$a_01_4 = {43 72 74 49 6d 70 6c 65 6d 65 6e 74 61 74 69 6f 6e 44 65 74 61 69 6c 73 } //1 CrtImplementationDetails
		$a_01_5 = {44 65 66 61 75 6c 74 44 6f 6d 61 69 6e 2e 44 6f 4e 6f 74 68 69 6e 67 } //1 DefaultDomain.DoNothing
		$a_01_6 = {63 6f 6f 6b 69 65 } //1 cookie
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=16
 
}