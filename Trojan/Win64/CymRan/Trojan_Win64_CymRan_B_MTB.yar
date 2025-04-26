
rule Trojan_Win64_CymRan_B_MTB{
	meta:
		description = "Trojan:Win64/CymRan.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {22 2b 43 79 6d 75 6c 61 74 65 46 69 6c 65 54 61 72 67 65 74 4e 61 6d 65 2b 22 2e 74 6d 70 } //2 "+CymulateFileTargetName+".tmp
		$a_01_1 = {6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 22 4d 53 58 6d 6c 32 2e 44 4f 4d 44 6f 63 75 6d 65 6e 74 } //2 new ActiveXObject("MSXml2.DOMDocument
		$a_01_2 = {6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 22 41 44 4f 44 42 2e 53 74 72 65 61 6d } //2 new ActiveXObject("ADODB.Stream
		$a_01_3 = {6f 62 6a 53 68 65 6c 6c 2e 52 75 6e 28 22 63 6d 64 2e 65 78 65 20 2f 63 } //2 objShell.Run("cmd.exe /c
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}