
rule Trojan_Win32_Prometei_APR_MTB{
	meta:
		description = "Trojan:Win32/Prometei.APR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 06 00 00 "
		
	strings :
		$a_01_0 = {88 15 ce 7e d0 00 c6 05 d0 7e d0 00 73 c6 05 d1 7e d0 00 65 a2 d2 7e d0 00 c6 05 d3 7e d0 00 75 88 15 d4 7e d0 00 c6 05 d5 7e d0 00 5f 88 0d d6 7e d0 00 c6 05 d7 7e d0 00 69 a2 d8 7e d0 00 c6 05 d9 7e d0 00 6c c6 05 da 7e d0 00 6f 88 0d db 7e d0 00 c6 05 dc 7e d0 00 2e a2 dd 7e d0 00 c6 05 de 7e d0 00 78 a2 df 7e d0 00 c6 05 e0 7e d0 00 00 c7 45 fc 00 00 00 00 ff 15 } //2
		$a_03_1 = {8a da 02 d9 30 18 85 c9 74 ?? 40 8d 98 eb ea ea ea 49 03 d7 3b de } //1
		$a_01_2 = {6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 66 69 72 65 77 61 6c 6c 20 64 65 6c 65 74 65 20 72 75 6c 65 20 6e 61 6d 65 3d 22 42 61 6e 6e 65 64 20 62 72 75 74 65 20 49 50 73 22 } //5 netsh advfirewall firewall delete rule name="Banned brute IPs"
		$a_01_3 = {41 75 64 69 74 70 6f 6c 20 2f 73 65 74 20 2f 73 75 62 63 61 74 65 67 6f 72 79 3a 22 4c 6f 67 6f 6e 22 20 2f 66 61 69 6c 75 72 65 3a 65 6e 61 62 6c 65 } //4 Auditpol /set /subcategory:"Logon" /failure:enable
		$a_01_4 = {74 00 65 00 6d 00 70 00 5c 00 73 00 65 00 74 00 75 00 70 00 5f 00 67 00 69 00 74 00 6c 00 6f 00 67 00 2e 00 74 00 78 00 74 00 } //3 temp\setup_gitlog.txt
		$a_01_5 = {73 00 71 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 sqhost.exe
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*5+(#a_01_3  & 1)*4+(#a_01_4  & 1)*3+(#a_01_5  & 1)*1) >=16
 
}