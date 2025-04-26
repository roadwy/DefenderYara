
rule Trojan_BAT_Hidtear_SA_MTB{
	meta:
		description = "Trojan:BAT/Hidtear.SA!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 61 61 61 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 63 72 79 70 74 30 72 5c 63 72 79 70 74 30 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 63 72 79 70 74 30 72 2e 70 64 62 } //1 C:\Users\aaa\source\repos\crypt0r\crypt0r\obj\Debug\crypt0r.pdb
		$a_01_1 = {69 00 6e 00 63 00 6f 00 72 00 72 00 65 00 63 00 74 00 20 00 6b 00 65 00 79 00 } //1 incorrect key
		$a_01_2 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //1 DisableTaskMgr
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}