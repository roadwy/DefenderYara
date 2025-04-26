
rule Trojan_Win32_Farfli_BD_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {66 75 63 6b 30 30 37 66 75 63 6b 6d 65 } //1 fuck007fuckme
		$a_01_1 = {5b 4e 75 6d 20 4c 6f 63 6b 5d } //1 [Num Lock]
		$a_01_2 = {5b 53 63 72 6f 6c 6c 20 4c 6f 63 6b 5d } //1 [Scroll Lock]
		$a_01_3 = {6c 6c 64 2e 32 33 69 70 61 76 64 61 } //1 lld.23ipavda
		$a_01_4 = {5b 50 72 69 6e 74 20 53 63 72 65 65 6e 5d } //1 [Print Screen]
		$a_01_5 = {79 75 61 6e 63 68 65 6e 67 } //1 yuancheng
		$a_01_6 = {57 61 6e 67 } //1 Wang
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}