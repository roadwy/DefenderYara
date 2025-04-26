
rule Trojan_Win64_Filecoder_PAZ_MTB{
	meta:
		description = "Trojan:Win64/Filecoder.PAZ!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 66 75 63 6b 65 64 } //2 Your files have been fucked
		$a_01_1 = {79 6f 75 20 77 69 6c 6c 20 67 65 74 20 79 6f 75 72 20 66 69 6c 65 73 20 62 61 63 6b } //2 you will get your files back
		$a_01_2 = {5c 52 45 41 44 4d 45 2e 74 78 74 } //1 \README.txt
		$a_01_3 = {5c 57 69 6e 64 6f 77 73 } //1 \Windows
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}