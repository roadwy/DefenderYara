
rule Trojan_Win32_Emotet_AH_MSR{
	meta:
		description = "Trojan:Win32/Emotet.AH!MSR,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 6a 65 63 74 31 2e 65 78 65 } //1 Project1.exe
		$a_01_1 = {6c 69 62 67 63 6a 2d 31 32 2e 64 6c 6c } //1 libgcj-12.dll
		$a_01_2 = {42 72 6f 6b 65 6e 20 70 72 6f 6d 69 73 65 } //1 Broken promise
		$a_01_3 = {50 72 6f 6d 69 73 65 20 61 6c 72 65 61 64 79 20 73 61 74 69 73 66 69 65 64 } //1 Promise already satisfied
		$a_01_4 = {46 75 74 75 72 65 20 61 6c 72 65 61 64 79 20 72 65 74 72 69 65 76 65 64 } //1 Future already retrieved
		$a_01_5 = {49 6e 66 69 6e 69 74 79 } //1 Infinity
		$a_01_6 = {73 70 65 63 69 61 6c 2e 64 61 74 } //1 special.dat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}