
rule Trojan_Win32_CryptInject_SBR_MSR{
	meta:
		description = "Trojan:Win32/CryptInject.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 65 78 62 6f 6d 62 } //1 Sexbomb
		$a_01_1 = {4e 65 64 72 69 76 65 6e } //1 Nedriven
		$a_01_2 = {4f 76 65 72 73 6b 72 69 76 66 75 6e 6b 74 69 6f 6e } //1 Overskrivfunktion
		$a_01_3 = {73 00 74 00 72 00 69 00 6e 00 67 00 20 00 73 00 70 00 61 00 } //1 string spa
		$a_01_4 = {53 61 6c 69 65 6e 63 79 } //1 Saliency
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_CryptInject_SBR_MSR_2{
	meta:
		description = "Trojan:Win32/CryptInject.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {62 47 6a 75 68 6b 62 4a 78 6f 7c 6b 78 62 6a 7d 6d 62 7a 6b 79 7a 34 68 67 7a } //1 bGjuhkbJxo|kxbj}mbzkyz4hgz
		$a_01_1 = {52 65 71 75 65 73 74 20 73 65 6e 74 } //1 Request sent
		$a_01_2 = {75 73 65 72 70 72 6f 66 69 6c 65 } //1 userprofile
		$a_01_3 = {6f 72 64 65 72 6d 65 2f 25 73 } //1 orderme/%s
		$a_01_4 = {44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 41 64 6f 62 65 5c 44 72 69 76 65 72 5c 64 77 67 5c 70 69 64 2e 74 78 74 } //1 Documents and Settings\Administrator\Adobe\Driver\dwg\pid.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_CryptInject_SBR_MSR_3{
	meta:
		description = "Trojan:Win32/CryptInject.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 6e 00 73 00 6f 00 32 00 38 00 41 00 45 00 2e 00 74 00 6d 00 70 00 } //1 C:\TEMP\nso28AE.tmp
		$a_01_1 = {62 00 75 00 73 00 68 00 77 00 68 00 61 00 63 00 6b 00 65 00 72 00 73 00 } //1 bushwhackers
		$a_01_2 = {63 00 75 00 72 00 72 00 65 00 6e 00 63 00 79 00 2e 00 78 00 6d 00 6c 00 } //1 currency.xml
		$a_01_3 = {50 00 65 00 6e 00 74 00 61 00 67 00 6f 00 6e 00 2e 00 64 00 6c 00 6c 00 } //1 Pentagon.dll
		$a_01_4 = {73 00 69 00 74 00 65 00 66 00 69 00 6c 00 65 00 73 00 } //1 sitefiles
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_CryptInject_SBR_MSR_4{
	meta:
		description = "Trojan:Win32/CryptInject.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0b 00 00 "
		
	strings :
		$a_01_0 = {70 69 70 65 6c 69 6e 65 20 62 6c 61 63 6b 6c 69 73 74 65 64 } //1 pipeline blacklisted
		$a_01_1 = {53 65 72 76 65 72 20 25 73 20 69 73 20 62 6c 61 63 6b 6c 69 73 74 65 64 } //1 Server %s is blacklisted
		$a_01_2 = {44 65 6c 65 74 65 55 72 6c 43 61 63 68 65 45 6e 74 72 79 } //1 DeleteUrlCacheEntry
		$a_01_3 = {43 6f 6f 6b 69 65 20 46 69 6c 65 } //1 Cookie File
		$a_01_4 = {75 73 65 72 20 2b 20 64 6f 6d 61 69 6e 20 2b 20 68 6f 73 74 20 6e 61 6d 65 } //1 user + domain + host name
		$a_01_5 = {6d 61 63 22 3a 22 25 73 22 2c 22 63 68 61 6e 6e 65 6c 22 3a 22 25 73 22 2c 22 73 79 73 22 3a 22 25 73 } //1 mac":"%s","channel":"%s","sys":"%s
		$a_01_6 = {51 6d 53 65 72 76 65 72 2e 70 64 62 } //1 QmServer.pdb
		$a_02_7 = {43 3a 5c 54 45 4d 50 5c [0-10] 2e 69 6e 69 } //1
		$a_01_8 = {68 74 74 70 3a 2f 2f 75 6e 69 6f 6e 2e 6a 75 7a 69 7a 6d 2e 63 6f 6d 2f 61 70 69 2f 6c 69 76 65 2f 73 65 72 76 65 72 } //2 http://union.juzizm.com/api/live/server
		$a_01_9 = {75 6e 69 6f 6e 2e 78 7a 33 34 35 2e 63 6e } //2 union.xz345.cn
		$a_01_10 = {64 68 38 37 35 2e 63 6e } //2 dh875.cn
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_02_7  & 1)*1+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2) >=10
 
}
rule Trojan_Win32_CryptInject_SBR_MSR_5{
	meta:
		description = "Trojan:Win32/CryptInject.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 64 6f 77 6e 2e [0-30] 3a 38 38 38 38 2f 6f 6b 2e 74 78 74 } //2
		$a_02_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 6d 00 69 00 2e 00 [0-30] 3a 00 38 00 38 00 38 00 38 00 2f 00 6b 00 69 00 6c 00 6c 00 2e 00 68 00 74 00 6d 00 6c 00 } //2
		$a_01_2 = {5c 00 5c 00 2e 00 5c 00 72 00 6f 00 6f 00 74 00 5c 00 73 00 75 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 } //1 \\.\root\subscription
		$a_01_3 = {66 00 75 00 63 00 6b 00 79 00 6f 00 75 00 6d 00 6d 00 32 00 5f 00 66 00 69 00 6c 00 74 00 65 00 72 00 } //1 fuckyoumm2_filter
		$a_01_4 = {73 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 5f 00 5f 00 74 00 69 00 6d 00 65 00 72 00 65 00 76 00 65 00 6e 00 74 00 20 00 77 00 68 00 65 00 72 00 65 00 20 00 74 00 69 00 6d 00 65 00 72 00 69 00 64 00 3d 00 22 00 66 00 75 00 63 00 6b 00 79 00 6f 00 75 00 6d 00 6d 00 32 00 5f 00 69 00 74 00 69 00 6d 00 65 00 72 00 } //1 select * from __timerevent where timerid="fuckyoumm2_itimer
	condition:
		((#a_03_0  & 1)*2+(#a_02_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}