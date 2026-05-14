
rule Trojan_Win32_GuLoader_SWA_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 66 6f 72 65 69 6e 74 65 6e 64 5c 73 70 68 61 65 72 6f 63 6f 62 61 6c 74 69 74 65 5c 72 65 61 64 65 } //1 \foreintend\sphaerocobaltite\reade
		$a_81_1 = {5c 62 6f 72 65 68 75 6c 6c 65 72 6e 65 5c 4b 6f 72 73 65 74 2e 62 69 6e } //1 \borehullerne\Korset.bin
		$a_81_2 = {4e 65 64 72 69 67 68 65 64 65 72 34 39 2e 69 6e 69 } //1 Nedrigheder49.ini
		$a_81_3 = {53 69 6b 6b 65 72 68 65 64 73 76 65 6e 74 69 6c 65 6e 73 2e 62 75 63 } //1 Sikkerhedsventilens.buc
		$a_81_4 = {54 68 75 6e 64 65 72 6c 69 6b 65 32 35 34 2e 62 61 63 } //1 Thunderlike254.bac
		$a_81_5 = {63 61 72 72 6f 6d 61 74 61 73 2e 63 6c 6f } //1 carromatas.clo
		$a_81_6 = {69 6d 70 6f 76 65 72 69 73 68 6d 65 6e 74 2e 79 6e 64 } //1 impoverishment.ynd
		$a_81_7 = {6e 6f 6e 6c 69 62 69 64 69 6e 6f 75 73 2e 6d 6f 6f } //1 nonlibidinous.moo
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}