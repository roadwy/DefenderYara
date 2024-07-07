
rule Trojan_Win32_Qakbot_RDA_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 00 63 00 6c 00 65 00 61 00 6e 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 ccleaner.exe
		$a_01_1 = {43 00 43 00 6c 00 65 00 61 00 6e 00 65 00 72 00 } //1 CCleaner
		$a_01_2 = {70 73 6f 72 69 61 74 69 66 6f 72 6d } //1 psoriatiform
		$a_01_3 = {6d 65 63 6f 6e 6f 70 68 61 67 69 73 6d } //1 meconophagism
		$a_01_4 = {73 74 61 72 63 68 6d 61 6e } //1 starchman
		$a_01_5 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllUnregisterServer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}