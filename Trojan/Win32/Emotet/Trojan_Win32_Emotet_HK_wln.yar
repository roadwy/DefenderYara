
rule Trojan_Win32_Emotet_HK_wln{
	meta:
		description = "Trojan:Win32/Emotet.HK!wln,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {69 68 61 76 65 6e 6f 70 61 73 73 } //1 ihavenopass
		$a_01_1 = {57 6c 61 6e 47 65 74 41 76 61 69 6c 61 62 6c 65 4e 65 74 77 6f 72 6b 4c 69 73 74 } //1 WlanGetAvailableNetworkList
		$a_01_2 = {2f 69 6e 64 65 78 2e 70 68 70 } //1 /index.php
		$a_01_3 = {63 3d 25 73 3a 25 73 } //1 c=%s:%s
		$a_03_4 = {65 6e 63 72 79 70 74 69 6f 6e 3a [0-0a] 4e 4f 4e 45 } //1
		$a_01_5 = {4e 4f 54 45 20 3a 20 57 4c 41 4e 5f 41 56 41 49 4c 41 42 4c 45 } //1 NOTE : WLAN_AVAILABLE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}