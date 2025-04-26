
rule Ransom_Win32_Flamingo_SBR_MSR{
	meta:
		description = "Ransom:Win32/Flamingo.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4b 69 6e 67 20 4f 66 20 52 61 6e 73 6f 6d } //1 King Of Ransom
		$a_01_1 = {45 4e 43 52 59 50 54 45 52 40 73 65 72 76 65 72 } //1 ENCRYPTER@server
		$a_01_2 = {52 65 61 64 54 68 69 73 2e 48 54 41 } //1 ReadThis.HTA
		$a_01_3 = {49 6e 66 6f 52 61 6e 73 2e 74 78 74 } //1 InfoRans.txt
		$a_01_4 = {68 74 74 70 73 3a 2f 2f 61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 } //1 https://api.telegram.org/bot
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}