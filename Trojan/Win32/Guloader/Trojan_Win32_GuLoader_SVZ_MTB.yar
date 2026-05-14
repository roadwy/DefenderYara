
rule Trojan_Win32_GuLoader_SVZ_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SVZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 55 6e 64 65 67 72 65 62 65 74 2e 67 69 66 } //1 \Undegrebet.gif
		$a_81_1 = {5c 73 63 72 75 62 6c 69 6b 65 2e 62 69 6e } //1 \scrublike.bin
		$a_81_2 = {43 65 72 65 63 6c 6f 74 68 73 2e 6b 6f 6d } //1 Cerecloths.kom
		$a_81_3 = {44 69 61 6d 61 6e 74 6d 69 6e 65 2e 74 69 70 } //1 Diamantmine.tip
		$a_81_4 = {6f 72 64 65 6e 73 6d 61 67 74 65 72 73 2e 63 68 61 } //1 ordensmagters.cha
		$a_81_5 = {76 69 72 6b 65 6b 72 66 74 65 72 6e 65 73 2e 73 61 6c } //1 virkekrfternes.sal
		$a_81_6 = {5c 4e 6f 6e 73 79 6e 74 68 65 74 69 63 2e 7a 69 70 } //1 \Nonsynthetic.zip
		$a_81_7 = {5c 70 69 65 74 6f 73 6f 5c 4b 72 61 70 69 6e 61 32 33 30 2e 69 6e 69 } //1 \pietoso\Krapina230.ini
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}