
rule Trojan_Win32_Farfli_MH_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {3a 5c 57 69 6e 64 6f 77 73 5c 44 4e 6f 6d 62 5c 4d 70 65 63 2e 6d 62 74 } //5 :\Windows\DNomb\Mpec.mbt
		$a_01_1 = {3a 2f 2f 77 68 74 74 79 2e 6f 73 73 2d 63 6e 2d 68 6f 6e 67 6b 6f 6e 67 2e 61 6c 69 79 75 6e 63 73 2e 63 6f 6d } //1 ://whtty.oss-cn-hongkong.aliyuncs.com
		$a_01_2 = {63 6d 64 2e 65 78 65 20 2f 63 20 64 65 6c } //1 cmd.exe /c del
		$a_01_3 = {5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 \shell\open\command
		$a_01_4 = {43 00 74 00 72 00 6c 00 2b 00 50 00 61 00 67 00 65 00 44 00 6f 00 77 00 6e 00 } //1 Ctrl+PageDown
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}
rule Trojan_Win32_Farfli_MH_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.MH!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 40 8b cf 99 f7 f9 8a 1c 32 89 55 08 8d 04 32 89 45 f4 0f b6 c3 03 45 f8 99 f7 f9 8b 45 f4 89 55 f8 8d 0c 32 8a 14 32 88 10 8b 55 fc 88 19 8b 4d 0c 0f b6 00 03 ca 0f b6 d3 03 c2 8b df 99 f7 fb 8a 04 32 30 01 ff 45 fc 8b 45 fc 3b 45 10 72 } //1
		$a_01_1 = {8b 45 08 8b 55 10 8b f9 83 45 10 04 8a 1c 30 0f b6 c3 03 02 03 45 fc 99 f7 ff 8a 04 32 89 55 fc 8d 3c 32 8b 55 08 ff 45 08 39 4d 08 88 04 32 88 1f 7c } //1
		$a_01_2 = {8b c3 33 d2 f7 75 10 8b 45 0c 88 1c 33 43 0f b6 04 02 89 07 83 c7 04 3b d9 7c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}