
rule Ransom_Win32_FileCoder_RHJ_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.RHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 09 00 00 "
		
	strings :
		$a_01_0 = {76 73 73 61 64 6d 69 6e 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 vssadmin Delete Shadows /all /quiet
		$a_01_1 = {77 6d 69 63 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //1 wmic shadowcopy delete
		$a_01_2 = {47 6c 69 74 63 68 42 79 74 65 2e 62 6d 70 } //1 GlitchByte.bmp
		$a_01_3 = {46 69 6e 64 4e 65 78 74 46 69 6c 65 41 } //1 FindNextFileA
		$a_01_4 = {2e 47 4c 42 54 } //1 .GLBT
		$a_01_5 = {69 66 20 79 6f 75 20 74 68 6f 75 67 68 74 20 74 68 69 73 20 72 61 6e 73 6f 6d 77 61 72 65 20 75 73 65 73 20 58 4f 52 } //1 if you thought this ransomware uses XOR
		$a_01_6 = {79 6f 75 27 72 65 20 77 72 6f 6e 67 } //1 you're wrong
		$a_01_7 = {73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //1 system32\drivers\etc\hosts
		$a_03_8 = {50 45 00 00 4c 01 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 02 26 00 2a 00 00 00 ?? 25 00 00 02 00 00 de 10 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_03_8  & 1)*2) >=10
 
}