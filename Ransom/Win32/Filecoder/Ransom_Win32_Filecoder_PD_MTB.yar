
rule Ransom_Win32_FileCoder_PD_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 00 50 00 5c 00 75 00 6c 00 6f 00 67 00 2e 00 74 00 78 00 74 00 } //1 UP\ulog.txt
		$a_01_1 = {52 00 65 00 6d 00 6f 00 76 00 65 00 64 00 2e 00 2e 00 } //1 Removed..
		$a_01_2 = {2e 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //1 .decrypted
		$a_01_3 = {55 00 50 00 69 00 72 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00 } //1 UPirate.exe
		$a_03_4 = {5c 55 50 69 72 61 74 65 5c 55 50 69 72 61 74 65 5c [0-20] 5c 55 50 69 72 61 74 65 2e 70 64 62 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}
rule Ransom_Win32_FileCoder_PD_MTB_2{
	meta:
		description = "Ransom:Win32/FileCoder.PD!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 00 73 00 5c 00 52 00 65 00 61 00 64 00 6d 00 65 00 2e 00 52 00 45 00 41 00 44 00 4d 00 45 00 } //1 %s\Readme.README
		$a_01_1 = {45 76 65 72 79 20 62 79 74 65 20 6f 6e 20 61 6e 79 20 74 79 70 65 73 20 6f 66 20 79 6f 75 72 20 64 65 76 69 63 65 73 20 77 61 73 20 65 6e 63 72 79 70 74 65 64 2e } //1 Every byte on any types of your devices was encrypted.
		$a_01_2 = {44 6f 6e 27 74 20 74 72 79 20 74 6f 20 75 73 65 20 62 61 63 6b 75 70 73 20 62 65 63 61 75 73 65 20 69 74 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 20 74 6f 6f 2e } //1 Don't try to use backups because it were encrypted too.
		$a_01_3 = {2e 00 70 00 79 00 73 00 61 00 } //1 .pysa
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}