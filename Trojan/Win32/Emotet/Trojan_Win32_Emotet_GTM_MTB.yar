
rule Trojan_Win32_Emotet_GTM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 89 45 f0 eb 12 8b 4d f4 83 c1 01 89 4d f4 8b 55 f0 83 c2 01 89 55 f0 81 7d f4 00 e1 f5 05 73 0a 8b 45 f0 8a 4d f4 88 08 eb db } //10
		$a_01_1 = {63 3a 5c 74 65 6d 70 5c 7e 65 6d 70 74 79 64 6f 63 2e 76 78 6d 6c } //1 c:\temp\~emptydoc.vxml
		$a_01_2 = {68 74 74 70 3a 2f 2f 6d 61 64 65 62 69 74 73 2e 63 6f 6d 2f } //1 http://madebits.com/
		$a_01_3 = {6b 61 74 61 6c 61 2e 64 6c 6c } //1 katala.dll
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 ShellExecute
		$a_01_6 = {47 41 49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //1 GAIsProcessorFeaturePresent
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=16
 
}