
rule Trojan_Win32_BlueStealer_SE_MTB{
	meta:
		description = "Trojan:Win32/BlueStealer.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {0f bf c0 89 85 38 fa ff ff db 85 38 fa ff ff dd 9d 30 fa ff ff dd 85 30 fa ff ff 83 3d 00 c0 46 00 00 75 08 } //1
		$a_81_1 = {61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 } //1 api.telegram.org/bot
		$a_81_2 = {73 65 6e 64 44 6f 63 75 6d 65 6e 74 3f 63 68 61 74 5f 69 64 3d } //1 sendDocument?chat_id=
		$a_81_3 = {33 66 62 64 30 34 66 35 2d 62 31 65 64 2d 34 30 36 30 2d 39 39 62 39 2d 66 63 61 37 66 66 35 39 63 31 31 33 } //1 3fbd04f5-b1ed-4060-99b9-fca7ff59c113
		$a_81_4 = {53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e } //1 Shell.Application
		$a_81_5 = {40 52 44 20 2f 53 20 2f 51 } //1 @RD /S /Q
		$a_81_6 = {48 4b 43 55 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 5c 2a 52 44 5f } //1 HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\*RD_
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}