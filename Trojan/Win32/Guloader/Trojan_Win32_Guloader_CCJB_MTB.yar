
rule Trojan_Win32_Guloader_CCJB_MTB{
	meta:
		description = "Trojan:Win32/Guloader.CCJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {75 64 73 6b 61 61 72 65 74 2e 69 6e 69 } //1 udskaaret.ini
		$a_01_1 = {67 72 6f 76 73 6f 72 74 62 66 72 5c 63 75 72 76 61 74 69 76 65 2e 62 6f 72 } //1 grovsortbfr\curvative.bor
		$a_01_2 = {63 79 6b 65 6c 73 6d 65 64 65 6e 73 2e 52 64 67 } //1 cykelsmedens.Rdg
		$a_01_3 = {68 76 73 6e 69 6e 67 65 6e 73 5c 68 61 61 6e 64 68 76 65 6c 73 65 73 6c 6f 76 65 73 2e 69 6e 69 } //1 hvsningens\haandhvelsesloves.ini
		$a_01_4 = {46 6f 6c 6b 65 74 69 6e 67 73 74 69 64 65 6e 64 65 6e 32 32 36 2e 53 74 61 } //1 Folketingstidenden226.Sta
		$a_01_5 = {46 61 62 65 6c 64 79 72 73 5c 70 72 6f 63 61 63 69 6f 75 73 6c 79 2e 64 6c 6c } //1 Fabeldyrs\procaciously.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}