
rule Trojan_Win32_Jurya_A{
	meta:
		description = "Trojan:Win32/Jurya.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 32 32 33 2e 32 34 34 2e 32 32 35 2e 33 3a } //2 http://223.244.225.3:
		$a_01_1 = {35 30 2f 49 6e 73 74 61 6c 6c 61 74 69 6f 6e 2e 65 78 65 } //1 50/Installation.exe
		$a_01_2 = {73 69 6e 67 6c 65 2d 6f 6b 2d 32 } //1 single-ok-2
		$a_01_3 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e } //1 Accept-Language: zh-cn
		$a_01_4 = {5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 \shell\open\command
		$a_01_5 = {6d 61 69 6c 74 6f 3a } //1 mailto:
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}