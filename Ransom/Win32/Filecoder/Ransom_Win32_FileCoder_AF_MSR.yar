
rule Ransom_Win32_FileCoder_AF_MSR{
	meta:
		description = "Ransom:Win32/FileCoder.AF!MSR,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_80_0 = {52 45 41 44 4d 45 2e 74 78 74 } //README.txt  2
		$a_80_1 = {53 6f 72 72 79 2c 20 62 75 74 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 6c 6f 63 6b 65 64 20 64 75 65 20 74 6f 20 61 20 63 72 69 74 69 63 61 6c 20 65 72 72 6f 72 20 69 6e 20 79 6f 75 72 20 73 79 73 74 65 6d } //Sorry, but your files are locked due to a critical error in your system  1
		$a_80_2 = {59 6f 75 20 68 61 76 65 20 74 6f 20 70 61 79 20 42 49 54 43 4f 49 4e 53 20 74 6f 20 67 65 74 20 79 6f 75 72 20 66 69 6c 65 20 64 65 63 6f 64 65 72 } //You have to pay BITCOINS to get your file decoder  1
		$a_80_3 = {46 75 63 6b 5f 74 68 69 73 5f 50 43 } //Fuck_this_PC  2
		$a_80_4 = {68 74 74 70 3a 2f 2f 72 65 73 74 6f 72 65 2d 6e 6f 77 2e 74 6f 70 2f 6f 6e 6c 69 6e 65 2d 63 68 61 74 } //http://restore-now.top/online-chat  10
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*2+(#a_80_4  & 1)*10) >=16
 
}