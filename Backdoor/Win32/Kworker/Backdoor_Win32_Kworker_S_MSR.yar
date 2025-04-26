
rule Backdoor_Win32_Kworker_S_MSR{
	meta:
		description = "Backdoor:Win32/Kworker.S!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 31 39 33 2e 32 39 2e 31 35 2e 31 34 37 } //1 https://193.29.15.147
		$a_01_1 = {6b 77 6f 72 6b 65 72 2f 75 38 3a 37 2d 65 76 } //1 kworker/u8:7-ev
		$a_01_2 = {4d 73 4d 70 45 6e 67 2e 65 78 65 } //1 MsMpEng.exe
		$a_01_3 = {2f 75 73 72 2f 6c 6f 63 61 6c 2f 62 69 6e 2f 75 70 64 61 74 65 2d 6e 6f 74 69 66 69 65 72 } //1 /usr/local/bin/update-notifier
		$a_01_4 = {41 63 63 65 73 73 2d 43 6f 6e 74 72 6f 6c 3a 20 61 57 35 6d 62 77 3d 3d } //1 Access-Control: aW5mbw==
		$a_01_5 = {4e 7a 67 36 51 55 4d 36 51 7a 41 36 4d 30 51 36 51 30 55 36 4d 7a 6b 4b 56 32 6c 75 5a 47 39 33 63 77 70 70 4d 7a 67 32 43 6a 41 75 } //1 Nzg6QUM6QzA6M0Q6Q0U6MzkKV2luZG93cwppMzg2CjAu
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}