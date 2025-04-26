
rule Trojan_Win32_SpyAgent_MD_MTB{
	meta:
		description = "Trojan:Win32/SpyAgent.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 62 6f 6f 74 } //1 .boot
		$a_01_1 = {2e 4a 4a 56 51 4a 4d 41 } //1 .JJVQJMA
		$a_01_2 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 54 68 69 6e 6b 56 61 6e 74 61 67 65 20 46 69 6e 67 65 72 70 72 69 6e 74 20 53 6f 66 74 77 61 72 65 5c 44 72 69 76 65 72 73 5c 73 6d 69 68 6c 70 2e 73 79 73 } //1 C:\Program Files\Common Files\ThinkVantage Fingerprint Software\Drivers\smihlp.sys
		$a_01_3 = {2f 64 75 6d 70 73 74 61 74 75 73 } //1 /dumpstatus
		$a_01_4 = {5c 53 79 73 74 65 6d 52 6f 6f 74 5c 73 79 73 74 65 6d 33 32 5c 42 4f 4f 54 56 49 } //1 \SystemRoot\system32\BOOTVI
		$a_01_5 = {55 00 62 00 69 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 } //1 Ubisoft Connect
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}