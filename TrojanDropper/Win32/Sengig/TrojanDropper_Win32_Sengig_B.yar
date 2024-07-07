
rule TrojanDropper_Win32_Sengig_B{
	meta:
		description = "TrojanDropper:Win32/Sengig.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {69 6e 73 74 2e 76 62 73 } //1 inst.vbs
		$a_01_1 = {25 73 5c 44 65 73 6b 74 6f 70 5c 53 65 61 72 63 68 2e 6c 6e 6b } //1 %s\Desktop\Search.lnk
		$a_01_2 = {44 00 72 00 6f 00 70 00 70 00 65 00 72 00 5c 00 52 00 65 00 61 00 64 00 4d 00 65 00 2e 00 74 00 78 00 74 00 } //1 Dropper\ReadMe.txt
		$a_01_3 = {25 00 43 00 44 00 25 00 31 00 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 63 00 68 00 72 00 6f 00 6d 00 65 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 73 00 65 00 61 00 72 00 63 00 68 00 65 00 6e 00 67 00 61 00 67 00 65 00 2e 00 63 00 6f 00 6d 00 } //1 %CD%1/c start chrome http://searchengage.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}