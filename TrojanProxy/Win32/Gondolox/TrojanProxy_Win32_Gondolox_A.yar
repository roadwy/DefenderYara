
rule TrojanProxy_Win32_Gondolox_A{
	meta:
		description = "TrojanProxy:Win32/Gondolox.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 5c 78 30 30 50 72 6f 78 79 53 65 72 76 65 72 5c 78 30 30 50 72 6f 78 79 45 6e 61 62 6c 65 5c 78 30 30 3d } //1 Software\Microsoft\Windows\CurrentVersion\Internet Settings\x00ProxyServer\x00ProxyEnable\x00=
		$a_03_1 = {53 75 62 6a 65 63 74 3a 20 25 73 0d 0a [0-08] 25 73 [0-06] 50 4f 53 54 20 68 74 74 70 3a 2f 2f 25 73 25 73 20 48 54 54 50 2f 31 2e 31 0d } //1
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {62 65 73 74 63 72 79 70 74 5f 75 70 64 61 74 65 } //1 bestcrypt_update
		$a_03_4 = {0f b6 1c 39 0f b6 d2 69 d2 ?? ?? ?? ?? 03 db 8d 2c 10 03 ed 33 dd 33 d8 81 c3 ?? ?? ?? ?? 83 c1 01 3b ce 8b c3 72 ?? 8b 5c 24 14 5d 89 03 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}