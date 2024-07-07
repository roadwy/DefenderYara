
rule Trojan_Win32_DelShad_SK_MTB{
	meta:
		description = "Trojan:Win32/DelShad.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 6c 73 61 73 73 2e 65 78 65 } //1 taskkill /f /im lsass.exe
		$a_01_1 = {73 68 75 74 64 6f 77 6e 20 2f 72 20 2f 74 20 31 35 30 20 2f 63 20 22 74 72 6f 6c 6f 6c 6f 6c 6f 6c 6f 6c 6f 6c 6f 6c 6f 6c 22 } //1 shutdown /r /t 150 /c "trolololololololol"
		$a_01_2 = {43 6f 6e 67 72 61 74 75 6c 61 74 69 6f 6e 73 2e 74 78 74 } //1 Congratulations.txt
		$a_01_3 = {65 78 63 75 73 65 20 6d 65 20 6d 61 74 65 20 79 6f 75 20 69 6e 73 74 61 6c 6c 65 64 20 6d 61 6c 77 61 72 65 20 6f 6e 20 74 68 65 20 73 79 73 74 65 6d } //1 excuse me mate you installed malware on the system
		$a_01_4 = {59 00 65 00 61 00 68 00 20 00 59 00 65 00 61 00 68 00 20 00 69 00 74 00 73 00 20 00 34 00 32 00 30 00 20 00 74 00 69 00 6d 00 65 00 } //1 Yeah Yeah its 420 time
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}