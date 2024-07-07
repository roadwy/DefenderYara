
rule Trojan_Win32_Zusy_BX_MTB{
	meta:
		description = "Trojan:Win32/Zusy.BX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 69 6f 65 73 67 77 65 69 6f 67 77 65 69 67 6a 65 6f 69 77 61 6a 67 } //2 Uioesgweiogweigjeoiwajg
		$a_01_1 = {56 73 65 69 75 67 73 65 6f 67 68 41 68 6f 73 67 68 73 65 68 } //2 VseiugseoghAhosghseh
		$a_01_2 = {6d 76 62 6f 69 73 72 67 73 65 6a 67 6f 69 65 73 6a 68 69 69 6a } //2 mvboisrgsejgoiesjhiij
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}