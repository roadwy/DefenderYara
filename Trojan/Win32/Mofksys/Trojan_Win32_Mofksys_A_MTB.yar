
rule Trojan_Win32_Mofksys_A_MTB{
	meta:
		description = "Trojan:Win32/Mofksys.A!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 6a 65 63 74 31 2e 75 45 78 57 61 74 63 68 } //1 Project1.uExWatch
		$a_01_1 = {6c 49 45 4f 62 6a 65 63 74 5f 44 6f 63 75 6d 65 6e 74 43 6f 6d 70 6c 65 74 65 } //1 lIEObject_DocumentComplete
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}