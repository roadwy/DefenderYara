
rule Ransom_MSIL_OsnoCrypt_MB_MTB{
	meta:
		description = "Ransom:MSIL/OsnoCrypt.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0b 00 00 "
		
	strings :
		$a_81_0 = {52 65 63 49 6e 73 74 72 75 63 74 2e 6f 73 6e 6f 6e 65 64 } //1 RecInstruct.osnoned
		$a_81_1 = {4f 73 6e 6f 20 52 61 6e 73 6f 6d 77 61 72 65 } //1 Osno Ransomware
		$a_81_2 = {4f 73 6e 6f 44 65 62 75 67 2e 74 78 74 } //1 OsnoDebug.txt
		$a_81_3 = {4f 73 6e 6f 47 61 6e 67 } //1 OsnoGang
		$a_81_4 = {70 72 6f 63 65 73 73 2e 65 6e 76 2e 68 6f 6f 6b 20 3d 20 27 4f 73 6e 6f 27 } //1 process.env.hook = 'Osno'
		$a_81_5 = {4f 73 6e 6f 20 52 61 6e 73 6f 6d 77 61 72 65 20 2d 20 48 6f 77 20 74 6f 20 72 65 63 6f 76 65 72 20 79 6f 75 72 20 66 69 6c 65 73 } //1 Osno Ransomware - How to recover your files
		$a_81_6 = {53 74 61 72 74 65 64 20 74 68 65 20 72 61 6e 73 6f 6d 77 61 72 65 21 } //1 Started the ransomware!
		$a_81_7 = {53 74 61 72 74 65 64 20 74 68 65 20 77 69 66 69 20 73 74 65 61 6c 65 72 } //1 Started the wifi stealer
		$a_81_8 = {42 72 6f 75 67 68 74 20 79 6f 75 20 62 79 20 4f 73 6e 6f 4b 65 79 6c 6f 67 67 65 72 } //1 Brought you by OsnoKeylogger
		$a_81_9 = {53 74 61 72 74 65 64 20 74 68 65 20 61 6e 74 69 2d 64 65 62 75 67 67 65 72 } //1 Started the anti-debugger
		$a_81_10 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 4f 73 6e 6f 20 52 61 6e 73 6f 6d 77 61 72 65 21 } //1 All your files are encrypted by Osno Ransomware!
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=10
 
}