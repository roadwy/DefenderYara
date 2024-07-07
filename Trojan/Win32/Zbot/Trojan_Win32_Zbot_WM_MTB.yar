
rule Trojan_Win32_Zbot_WM_MTB{
	meta:
		description = "Trojan:Win32/Zbot.WM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_02_0 = {92 52 d0 14 c7 05 90 01 04 78 11 d0 14 66 89 35 c8 16 d1 14 c7 05 90 01 04 bd 52 d0 14 c7 05 90 01 04 64 11 d0 14 66 89 35 d8 16 d1 14 c7 05 90 01 04 f7 52 d0 14 c7 05 90 01 04 50 11 d0 14 90 00 } //10
		$a_01_1 = {8b 45 7c 8b 40 04 8b 55 64 8a 04 38 8b 4d 50 ff 45 64 88 04 11 8b 45 7c 8b 48 08 47 ff 45 58 ff 45 5c 3b f9 89 7d 60 0f 82 d7 fe ff ff } //10
		$a_01_2 = {31 39 35 2e 31 38 39 2e 32 34 36 2e 32 33 35 } //1 195.189.246.235
		$a_80_3 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e } //software\microsoft\windows\currentversion\run  1
	condition:
		((#a_02_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1) >=22
 
}