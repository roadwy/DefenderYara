
rule Trojan_Win32_Tovkater_B{
	meta:
		description = "Trojan:Win32/Tovkater.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 6e 00 73 00 79 00 32 00 38 00 42 00 38 00 2e 00 74 00 6d 00 70 00 } //1 C:\TEMP\nsy28B8.tmp
		$a_01_1 = {73 00 68 00 6d 00 67 00 72 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00 } //1 shmgrate.exe
		$a_01_2 = {59 00 20 00 67 00 61 00 6d 00 65 00 6d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 2e 00 64 00 6c 00 6c 00 } //1 Y gamemonitor.dll
		$a_01_3 = {7a 00 77 00 65 00 72 00 74 00 2e 00 65 00 78 00 65 00 } //1 zwert.exe
		$a_01_4 = {6d 00 73 00 69 00 6d 00 6e 00 2e 00 65 00 78 00 65 00 } //1 msimn.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}