
rule TrojanSpy_Win32_Bancos_OJ{
	meta:
		description = "TrojanSpy:Win32/Bancos.OJ,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {7c 2e 43 33 ff 8d 45 f8 50 8b 45 fc e8 ?? ?? ?? ff 8b d0 2b d7 b9 01 00 00 00 8b 45 fc e8 ?? ?? ?? ff 8b 55 f8 8b c6 e8 ?? ?? ?? ff 47 4b 75 d5 } //5
		$a_01_1 = {2f 2f 3a 70 74 74 68 } //1 //:ptth
		$a_01_2 = {74 78 74 2e 6e 73 6d 2f } //1 txt.nsm/
		$a_01_3 = {6c 6d 74 68 2e 6b 6f 2f } //1 lmth.ko/
		$a_01_4 = {6c 6d 74 68 2e 6e 73 6d } //1 lmth.nsm
		$a_01_5 = {6f 72 6b 75 74 2e 63 6f 6d 2e 62 72 } //1 orkut.com.br
		$a_01_6 = {57 69 6e 64 6f 77 73 20 4c 69 76 65 20 4d 65 73 73 65 6e 67 65 72 } //1 Windows Live Messenger
		$a_01_7 = {4d 53 4e 54 69 6d 65 72 } //1 MSNTimer
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}