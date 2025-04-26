
rule TrojanSpy_Win32_Bancos_AB{
	meta:
		description = "TrojanSpy:Win32/Bancos.AB,SIGNATURE_TYPE_PEHSTR,15 00 15 00 08 00 00 "
		
	strings :
		$a_01_0 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 65 00 74 00 63 00 5c 00 68 00 6f 00 73 00 74 00 73 00 } //10 \system32\drivers\etc\hosts
		$a_01_1 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 57 00 37 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 68 00 6f 00 73 00 74 00 73 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //10 C:\Users\W7\Desktop\hosts\Project1.vbp
		$a_01_2 = {77 77 77 2e 73 61 6e 74 61 6e 64 65 72 2e 63 6f 6d 2e 6d 78 } //1 www.santander.com.mx
		$a_01_3 = {77 77 77 2e 73 61 6e 74 61 6e 64 65 72 2e 63 6f 6d } //1 www.santander.com
		$a_01_4 = {73 61 6e 74 61 6e 64 65 72 2e 63 6f 6d 2e 6d 78 } //1 santander.com.mx
		$a_01_5 = {73 61 6e 74 61 6e 64 65 72 2e 63 6f 6d } //1 santander.com
		$a_01_6 = {65 6e 6c 61 63 65 2e 73 61 6e 74 61 6e 64 65 72 2d 73 65 72 66 69 6e 2e 63 6f 6d } //1 enlace.santander-serfin.com
		$a_01_7 = {54 68 69 73 20 69 73 20 61 20 73 61 6d 70 6c 65 20 48 4f 53 54 53 20 66 69 6c 65 20 75 73 65 64 20 62 79 20 4d 69 63 72 6f 73 6f 66 74 20 54 43 50 2f 49 50 20 66 6f 72 20 57 69 6e 64 6f 77 73 2e } //1 This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=21
 
}