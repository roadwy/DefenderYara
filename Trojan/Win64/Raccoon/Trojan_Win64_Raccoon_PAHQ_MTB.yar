
rule Trojan_Win64_Raccoon_PAHQ_MTB{
	meta:
		description = "Trojan:Win64/Raccoon.PAHQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 65 73 6b 74 6f 70 5f 73 63 72 65 65 6e 73 68 6f 74 2e 70 6e 67 } //1 desktop_screenshot.png
		$a_01_1 = {58 4f 52 5f 49 4e 4a 45 43 54 4f 52 2b 41 42 45 2b 44 50 41 50 49 2b 57 41 4c 4c 45 54 53 2b 4d 45 53 53 45 4e 47 45 52 53 2b 46 54 50 2b 53 43 52 45 45 4e 53 48 4f 54 } //2 XOR_INJECTOR+ABE+DPAPI+WALLETS+MESSENGERS+FTP+SCREENSHOT
		$a_01_2 = {73 79 73 74 65 6d 5f 69 6e 66 6f 2e 6a 73 6f 6e } //1 system_info.json
		$a_01_3 = {49 6e 6a 65 63 74 65 64 2d 48 65 61 64 65 72 3a 20 45 76 69 6c } //2 Injected-Header: Evil
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=6
 
}