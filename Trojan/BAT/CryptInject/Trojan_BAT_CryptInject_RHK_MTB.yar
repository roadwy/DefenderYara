
rule Trojan_BAT_CryptInject_RHK_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.RHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0a 00 00 "
		
	strings :
		$a_03_0 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 30 00 00 9e 0b 00 00 18 00 00 00 00 00 00 ce bd } //2
		$a_01_1 = {00 00 01 00 01 00 1a 20 00 00 00 00 00 00 a8 0d 00 00 01 00 } //2
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_3 = {6b 65 72 6e 65 6c 33 32 2e 64 6c 6c } //1 kernel32.dll
		$a_01_4 = {73 65 6e 64 65 72 } //1 sender
		$a_01_5 = {4f 70 65 6e 46 69 6c 65 } //1 OpenFile
		$a_01_6 = {46 6f 72 6d 31 5f 4c 6f 61 64 } //1 Form1_Load
		$a_01_7 = {6e 61 6d 65 4f 66 43 75 73 74 } //1 nameOfCust
		$a_01_8 = {45 70 69 73 6f 64 65 } //1 Episode
		$a_01_9 = {58 50 53 20 50 72 69 6e 74 69 6e 67 } //1 XPS Printing
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=12
 
}