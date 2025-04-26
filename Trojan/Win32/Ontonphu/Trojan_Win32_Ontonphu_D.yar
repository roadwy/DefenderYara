
rule Trojan_Win32_Ontonphu_D{
	meta:
		description = "Trojan:Win32/Ontonphu.D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 0f b6 44 18 ff 2b 45 f8 2b c3 33 45 f8 89 45 f4 8d 45 f0 8a 55 f4 e8 ?? ?? ?? ?? 8b 55 f0 8b c7 e8 ?? ?? ?? ?? 43 4e 75 d4 33 c0 } //2
		$a_03_1 = {68 20 02 00 00 6a 20 6a 02 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 1e 4b 85 db 7c ?? 43 33 ff 8b 44 fe 04 } //2
		$a_01_2 = {2f 67 73 78 72 2f 63 6d 64 2e 70 68 70 } //1 /gsxr/cmd.php
		$a_03_3 = {2f 63 6d 64 2e 70 68 70 [0-80] 5c 41 75 74 68 6f 72 69 7a 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 4c 69 73 74 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}