
rule Trojan_Win32_Qhost_FR{
	meta:
		description = "Trojan:Win32/Qhost.FR,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 74 6d 70 5c 65 6e 63 72 79 70 74 5f 79 6f 75 74 75 62 65 2e 62 61 74 } //1 .tmp\encrypt_youtube.bat
		$a_01_1 = {25 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //1 %:\WINDOWS\system32\drivers\etc\hosts
		$a_01_2 = {25 3a 2f 2f 79 6f 75 74 75 62 65 2e 69 73 2d 6c 6f 73 74 2e 6f 72 67 2f 6e 6f 68 75 70 2f 74 6f 74 61 6c 5f 76 69 73 69 74 61 73 2e 70 68 70 } //1 %://youtube.is-lost.org/nohup/total_visitas.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}