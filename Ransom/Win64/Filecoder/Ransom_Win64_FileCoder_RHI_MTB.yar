
rule Ransom_Win64_FileCoder_RHI_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.RHI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0b 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //1 Go build ID:
		$a_01_1 = {76 73 73 61 64 6d 69 6e 74 61 73 6b 6b 69 6c 6c 62 6f 6f 74 } //1 vssadmintaskkillboot
		$a_01_2 = {58 4f 52 4b 65 79 53 74 72 65 61 6d } //1 XORKeyStream
		$a_01_3 = {70 72 6f 63 65 73 73 47 65 74 41 64 61 70 74 65 72 73 49 6e 66 6f } //1 processGetAdaptersInfo
		$a_01_4 = {6d 79 64 65 73 6b 74 6f 70 71 6f 73 2e 65 78 65 } //1 mydesktopqos.exe
		$a_01_5 = {42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45 59 } //1 BEGIN PUBLIC KEY
		$a_01_6 = {73 79 73 63 61 6c 6c 2e 46 69 6e 64 4e 65 78 74 46 69 6c 65 } //1 syscall.FindNextFile
		$a_01_7 = {73 79 73 63 61 6c 6c 2e 57 72 69 74 65 46 69 6c 65 } //1 syscall.WriteFile
		$a_01_8 = {52 4c 6f 63 6b 65 72 } //1 RLocker
		$a_01_9 = {66 69 6c 65 73 64 65 6c 65 74 65 2f 71 75 69 65 74 4c 6f 63 6b 65 72 } //1 filesdelete/quietLocker
		$a_03_10 = {50 45 00 00 64 86 0f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 03 00 00 5e 11 00 00 2a 01 00 00 00 00 00 40 5c 06 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_03_10  & 1)*2) >=12
 
}