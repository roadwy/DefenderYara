
rule Trojan_Win32_TinyMet_ibt{
	meta:
		description = "Trojan:Win32/TinyMet!ibt,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {74 69 6e 79 6d 65 74 2e 63 6f 6d } //1 tinymet.com
		$a_01_1 = {74 69 6e 79 6d 65 74 2e 65 78 65 20 32 20 68 6f 73 74 2e 63 6f 6d 20 34 34 33 } //1 tinymet.exe 2 host.com 443
		$a_01_2 = {55 73 61 67 65 3a 20 74 69 6e 79 6d 65 74 2e 65 78 65 20 5b 74 72 61 6e 73 70 6f 72 74 5d 20 4c 48 4f 53 54 20 4c 50 4f 52 54 } //1 Usage: tinymet.exe [transport] LHOST LPORT
		$a_01_3 = {6c 69 6b 65 20 54 52 41 4e 53 50 4f 52 54 5f 4c 48 4f 53 54 5f 4c 50 4f 52 54 2e 65 78 65 } //1 like TRANSPORT_LHOST_LPORT.exe
		$a_01_4 = {77 69 6c 6c 20 75 73 65 20 72 65 76 65 72 73 65 5f 68 74 74 70 73 20 61 6e 64 20 63 6f 6e 6e 65 63 74 20 74 6f 20 68 6f 73 74 2e 63 6f 6d 3a 34 34 33 } //1 will use reverse_https and connect to host.com:443
		$a_01_5 = {73 65 74 74 69 6e 67 20 74 68 65 20 66 69 6c 65 6e 61 6d 65 20 74 6f 20 22 32 5f 68 6f 73 74 2e 63 6f 6d 5f 34 34 33 2e 65 78 65 22 20 61 6e 64 20 72 75 6e 6e 69 6e 67 20 69 74 20 77 69 74 68 6f } //1 setting the filename to "2_host.com_443.exe" and running it witho
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}