
rule Trojan_Win32_Vidar_AVI_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AVI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_03_0 = {50 6a 00 53 ff 15 ?? ?? ?? ?? 56 89 45 fc ff 15 } //2
		$a_01_1 = {4d 61 6c 6f 6c 6f 20 69 73 20 61 20 76 6f 6c 63 61 6e 69 63 20 69 73 6c 61 6e 64 20 69 6e 20 74 68 65 20 50 61 63 69 66 69 63 20 4f 63 65 61 6e } //1 Malolo is a volcanic island in the Pacific Ocean
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 6d 6f 6e 65 72 6f 2d 70 72 6f 6a 65 63 74 5c 6d 6f 6e 65 72 6f 2d 63 6f 72 65 } //1 SOFTWARE\monero-project\monero-core
		$a_01_3 = {5c 4d 6f 6e 65 72 6f 5c 77 61 6c 6c 65 74 2e 6b 65 79 73 } //1 \Monero\wallet.keys
		$a_01_4 = {5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 46 69 6c 65 5a 69 6c 6c 61 5c 72 65 63 65 6e 74 73 65 72 76 65 72 73 2e 78 6d 6c } //1 \AppData\Roaming\FileZilla\recentservers.xml
		$a_01_5 = {49 6e 64 6f 6e 65 73 69 61 20 73 70 79 69 6e 67 20 73 63 61 6e 64 61 6c 20 64 65 76 65 6c 6f 70 65 64 20 66 72 6f 6d 20 61 6c 6c 65 67 61 74 69 6f 6e 73 } //1 Indonesia spying scandal developed from allegations
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}