
rule Trojan_BAT_Dllinject_KB{
	meta:
		description = "Trojan:BAT/Dllinject.KB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {3c 6b 72 6e 6c 5f 41 63 74 69 76 61 74 65 64 3e 64 5f 5f 31 31 30 } //1 <krnl_Activated>d__110
		$a_01_1 = {6b 72 6e 6c 73 73 2e 65 78 65 } //1 krnlss.exe
		$a_01_2 = {69 6e 6a 65 63 74 69 6f 6e } //1 injection
		$a_01_3 = {6b 72 6e 6c 5f 6d 6f 6e 61 63 6f } //1 krnl_monaco
		$a_01_4 = {6b 72 6e 6c 73 73 2e 6b 72 6e 6c 2e 72 65 73 6f 75 72 63 65 73 } //1 krnlss.krnl.resources
		$a_01_5 = {6b 72 6e 6c 5f 4c 6f 61 64 } //1 krnl_Load
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}