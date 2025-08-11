
rule Trojan_Win32_Blackmoon_AYA_MTB{
	meta:
		description = "Trojan:Win32/Blackmoon.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {72 2e 63 76 63 76 6e 2e 63 6e 2f 41 43 45 2f 53 63 76 68 6f 73 74 2e 65 78 65 } //2 r.cvcvn.cn/ACE/Scvhost.exe
		$a_01_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 57 4f 57 36 34 5c 53 63 76 68 6f 73 74 2e 65 78 65 } //2 C:\Windows\SysWOW64\Scvhost.exe
		$a_01_2 = {42 6c 61 63 6b 4d 6f 6f 6e 20 52 75 6e 54 69 6d 65 20 45 72 72 6f 72 3a } //1 BlackMoon RunTime Error:
		$a_01_3 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 58 4e 2d 44 54 5a 59 20 2f 54 52 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 57 4f 57 36 34 5c 56 49 50 2e 65 78 65 20 2f 64 65 6c 61 79 } //1 schtasks /create /tn XN-DTZY /TR C:\Windows\SysWOW64\VIP.exe /delay
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}