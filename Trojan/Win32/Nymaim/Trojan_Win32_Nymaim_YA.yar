
rule Trojan_Win32_Nymaim_YA{
	meta:
		description = "Trojan:Win32/Nymaim.YA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {79 62 68 69 6e 6c 6c 79 74 6e 68 67 6c 6d 76 73 69 } //1 ybhinllytnhglmvsi
		$a_01_1 = {6a 66 6c 6c 7a 75 6e 64 70 78 6d 78 70 73 7a 6c } //1 jfllzundpxmxpszl
		$a_01_2 = {70 62 6b 69 6c 66 6b 79 75 } //1 pbkilfkyu
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}