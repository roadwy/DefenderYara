
rule Trojan_Win32_Agent_KZ{
	meta:
		description = "Trojan:Win32/Agent.KZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 65 61 6c 41 75 64 6f 5c 41 63 39 37 } //1 RealAudo\Ac97
		$a_01_1 = {43 57 45 6e 6a 65 63 74 2e 65 78 65 } //1 CWEnject.exe
		$a_01_2 = {4b 47 44 61 65 6d 6f 6d 2e 65 78 65 } //1 KGDaemom.exe
		$a_01_3 = {5b 23 23 4d 69 63 72 6f 73 6f 66 74 23 23 5d } //1 [##Microsoft##]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}