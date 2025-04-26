
rule Ransom_Win32_FileCoder_MBK_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.MBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 All your files has been encrypted
		$a_81_1 = {52 45 41 44 4d 45 2e 74 78 74 } //1 README.txt
		$a_81_2 = {74 68 65 20 77 68 6f 6c 65 20 64 6f 77 6e 6c 6f 61 64 65 64 20 69 6e 66 6f 20 77 69 6c 6c 20 70 6f 73 74 20 6f 6e 20 70 75 62 6c 69 63 20 6e 65 77 73 20 77 65 62 73 69 74 65 } //1 the whole downloaded info will post on public news website
		$a_81_3 = {57 65 20 68 61 76 65 20 61 6c 73 6f 20 64 6f 77 6e 6c 6f 61 64 65 64 20 61 20 6c 6f 74 20 6f 66 20 70 72 69 76 61 74 65 20 64 61 74 61 20 66 72 6f 6d 20 79 6f 75 72 20 6e 65 74 77 6f 72 6b } //1 We have also downloaded a lot of private data from your network
		$a_81_4 = {70 75 74 20 74 68 69 73 20 6b 65 79 3a } //1 put this key:
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}