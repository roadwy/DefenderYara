
rule Trojan_Win32_GuLoader_RAS_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {70 72 63 65 64 65 6e 73 65 6e 73 5c 42 61 72 73 65 6c 73 6f 72 6c 6f 76 65 72 6e 65 73 5c 72 65 74 73 68 6a 6c 70 65 6e 73 } //1 prcedensens\Barselsorlovernes\retshjlpens
		$a_81_1 = {25 50 6f 69 6e 74 65 72 73 25 5c 50 72 65 76 61 6c 69 64 6c 79 32 34 36 5c 53 61 6d 6d 65 6e 6b 6c 75 6d 70 65 74 } //1 %Pointers%\Prevalidly246\Sammenklumpet
		$a_81_2 = {6d 61 73 74 75 72 62 61 74 69 6f 6e 20 6c 73 65 72 69 6e 64 65 72 6e 65 } //1 masturbation lserinderne
		$a_81_3 = {74 68 61 6b 75 72 61 74 65 2e 65 78 65 } //1 thakurate.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}