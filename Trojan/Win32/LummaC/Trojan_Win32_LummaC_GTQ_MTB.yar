
rule Trojan_Win32_LummaC_GTQ_MTB{
	meta:
		description = "Trojan:Win32/LummaC.GTQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 4c 04 ?? 89 c2 81 ca ?? ?? ?? ?? 31 ca 89 d1 81 f1 ?? ?? ?? ?? 83 e2 ?? 8d 0c 51 fe c1 88 4c 04 ?? 89 c1 83 e1 } //10
		$a_03_1 = {0f b6 b4 04 ?? ?? ?? ?? 89 c2 31 ca 21 f2 31 ca b3 9d 28 d3 88 9c 04 ?? ?? ?? ?? 40 49 3d } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}