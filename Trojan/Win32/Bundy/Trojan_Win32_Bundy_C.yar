
rule Trojan_Win32_Bundy_C{
	meta:
		description = "Trojan:Win32/Bundy.C,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6f 70 65 6e 00 74 61 73 6b 6b 69 6c 6c 00 2f 66 20 2f 69 6d 20 4b 53 57 65 62 53 68 69 65 6c 64 2e 65 78 65 00 6f 70 65 6e 20 74 61 73 6b 6b 69 6c 6c } //1
		$a_01_1 = {5c 6b 69 6e 67 73 6f 66 74 00 73 70 69 74 65 73 70 2e 64 61 74 } //1
		$a_01_2 = {5c 49 6e 74 65 72 6e 61 74 20 45 78 70 6c 6f 72 61 72 } //1 \Internat Explorar
		$a_01_3 = {69 66 20 65 78 69 73 74 } //1 if exist
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}