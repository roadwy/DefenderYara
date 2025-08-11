
rule Trojan_Win32_GuLoader_RAR_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {73 74 61 70 68 79 6c 6f 63 6f 63 63 69 63 20 67 61 72 62 6c 69 6e 67 73 20 6f 76 65 72 62 79 67 6e 69 6e 67 65 72 6e 65 } //1 staphylococcic garblings overbygningerne
		$a_81_1 = {66 6f 72 74 72 6e 67 6e 69 6e 67 65 72 } //1 fortrngninger
		$a_81_2 = {72 65 66 72 61 67 61 62 69 6c 69 74 79 20 67 6f 6d 61 73 74 61 } //1 refragability gomasta
		$a_81_3 = {70 72 65 73 75 62 6d 69 74 74 69 6e 67 20 6b 6c 61 75 73 74 72 6f 66 6f 62 69 2e 65 78 65 } //1 presubmitting klaustrofobi.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}