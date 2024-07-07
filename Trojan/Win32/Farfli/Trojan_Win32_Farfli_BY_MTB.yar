
rule Trojan_Win32_Farfli_BY_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {f7 f9 8b 45 ec 2a d0 88 14 38 40 3b 45 fc 89 45 ec 72 } //2
		$a_01_1 = {63 6d 64 2e 65 78 65 20 2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e 20 32 26 25 73 } //1 cmd.exe /c ping 127.0.0.1 -n 2&%s
		$a_01_2 = {25 73 5c 25 73 2e 65 78 65 } //1 %s\%s.exe
		$a_01_3 = {5b 3a 70 72 69 6e 74 3a 5d } //1 [:print:]
		$a_01_4 = {76 6d 70 30 } //1 vmp0
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}