
rule Trojan_Win64_Stealer_MX_MTB{
	meta:
		description = "Trojan:Win64/Stealer.MX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 39 c8 0f 84 17 94 09 00 66 89 10 0f b7 50 0a 48 83 c0 02 66 85 d2 } //1
		$a_01_1 = {52 75 6e 74 69 6e 65 20 42 72 6f 6b 65 72 2e 65 78 65 } //1 Runtine Broker.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win64_Stealer_MX_MTB_2{
	meta:
		description = "Trojan:Win64/Stealer.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 79 53 65 63 72 65 74 4c 6f 61 64 65 72 4b 65 79 31 32 33 00 00 00 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00 43 00 3a 00 5c 00 00 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 56 00 4d 00 77 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Stealer_MX_MTB_3{
	meta:
		description = "Trojan:Win64/Stealer.MX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {75 1f 41 8b c0 b9 40 00 00 00 83 e0 3f 2b c8 48 d3 ca 49 33 d0 48 89 15 db 5b 05 00 48 83 c4 28 } //1
		$a_01_1 = {4f 62 66 75 73 63 61 74 69 6f 6e 20 6c 61 79 65 72 20 61 63 74 69 76 65 20 2d 20 73 79 73 63 61 6c 6c 73 20 65 6e 63 72 79 70 74 65 64 20 69 6e 20 6d 65 6d 6f 72 79 } //1 Obfuscation layer active - syscalls encrypted in memory
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win64_Stealer_MX_MTB_4{
	meta:
		description = "Trojan:Win64/Stealer.MX!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 54 45 41 4c 45 52 20 52 41 50 4f 52 } //5 STEALER RAPOR
		$a_01_1 = {54 65 6c 65 67 72 61 6d 20 57 65 62 20 6f 74 75 72 75 6d 75 20 62 75 6c 75 6e 64 75 } //1 Telegram Web oturumu bulundu
		$a_01_2 = {45 78 74 72 61 63 74 41 6c 6c 42 72 6f 77 73 65 72 43 6f 6f 6b 69 65 73 } //1 ExtractAllBrowserCookies
		$a_01_3 = {64 69 73 63 6f 72 64 2e 63 6f 6d 2f 61 70 69 2f 77 65 62 68 6f 6f 6b 73 } //1 discord.com/api/webhooks
		$a_01_4 = {62 61 73 6c 61 74 69 6c 64 69 } //1 baslatildi
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}