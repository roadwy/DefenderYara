
rule Trojan_Win64_ShellCodeRunner_RPH_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.RPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {5c 6d 61 6c 64 65 76 5c 21 63 6f 64 65 2d 73 65 63 74 69 6f 6e 5c 21 53 68 65 6c 6c 63 6f 64 65 5c 53 68 65 6c 6c 63 6f 64 65 2d 74 65 73 74 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 53 68 65 6c 6c 63 6f 64 65 2d 74 65 73 74 2e 70 64 62 } //10 \maldev\!code-section\!Shellcode\Shellcode-test\x64\Release\Shellcode-test.pdb
		$a_01_1 = {5c 6d 61 6c 64 65 76 5c 21 63 6f 64 65 2d 73 65 63 74 69 6f 6e 5c 21 53 68 65 6c 6c 63 6f 64 65 5c 53 68 65 6c 6c 63 6f 64 65 2d 6f 62 66 75 73 63 61 74 65 64 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 53 68 65 6c 6c 63 6f 64 65 2d 6f 62 66 75 73 63 61 74 65 64 2e 70 64 62 } //10 \maldev\!code-section\!Shellcode\Shellcode-obfuscated\x64\Release\Shellcode-obfuscated.pdb
		$a_01_2 = {5c 6d 61 6c 64 65 76 5c 63 6f 64 65 2d 73 65 63 74 69 6f 6e 5c 66 75 64 2d 63 6d 64 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 66 75 64 2d 63 6d 64 2e 70 64 62 } //10 \maldev\code-section\fud-cmd\x64\Release\fud-cmd.pdb
		$a_01_3 = {5c 6d 61 6c 64 65 76 5c 21 63 6f 64 65 2d 73 65 63 74 69 6f 6e 5c 66 75 64 2d 63 6d 64 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 66 75 64 2d 63 6d 64 2e 70 64 62 } //10 \maldev\!code-section\fud-cmd\x64\Release\fud-cmd.pdb
		$a_01_4 = {63 75 72 6c 5f 65 61 73 79 5f 70 65 72 66 6f 72 6d 20 63 61 6e 6e 6f 74 20 62 65 20 65 78 65 63 75 74 65 64 20 69 66 20 74 68 65 20 43 55 52 4c 20 68 61 6e 64 6c 65 20 69 73 20 75 73 65 64 20 69 6e 20 61 20 4d 75 6c 74 69 50 65 72 66 6f 72 6d 2e } //1 curl_easy_perform cannot be executed if the CURL handle is used in a MultiPerform.
		$a_03_5 = {68 74 74 70 73 3a 2f 2f [0-90] 2e 74 78 74 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=12
 
}