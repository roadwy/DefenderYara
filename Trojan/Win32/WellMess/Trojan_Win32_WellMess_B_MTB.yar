
rule Trojan_Win32_WellMess_B_MTB{
	meta:
		description = "Trojan:Win32/WellMess.B!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {62 6f 74 6c 69 62 2e 7a 33 32 64 65 63 6f 64 65 } //1 botlib.z32decode
		$a_01_1 = {62 6f 74 6c 69 62 2e 7a 33 32 64 65 63 6f 64 65 53 74 72 69 6e 67 } //1 botlib.z32decodeString
		$a_01_2 = {62 6f 74 6c 69 62 2e 53 65 6e 64 2e 66 75 6e 63 31 } //1 botlib.Send.func1
		$a_01_3 = {62 6f 74 6c 69 62 2e 53 65 6e 64 44 2e 66 75 6e 63 31 } //1 botlib.SendD.func1
		$a_01_4 = {62 6f 74 6c 69 62 2e 69 6e 69 74 } //1 botlib.init
		$a_01_5 = {66 61 6b 65 4c 6f 63 6b 65 72 } //1 fakeLocker
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}