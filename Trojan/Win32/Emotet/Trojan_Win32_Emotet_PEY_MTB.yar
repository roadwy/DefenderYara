
rule Trojan_Win32_Emotet_PEY_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PEY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {8a 04 0e 81 e2 ff 00 00 00 03 c2 99 f7 fd 8a 04 0a 8b 54 24 ?? 32 04 1a 43 88 43 } //1
		$a_02_1 = {0f b6 00 0f b6 d2 03 c2 99 f7 fb 8a 04 0a 8b 55 ?? 32 04 3a 88 07 } //1
		$a_81_2 = {36 75 30 43 48 6d 38 37 6d 73 48 68 64 58 7c 7a 37 63 4a 47 72 30 4f 30 7b 4c 3f 79 76 3f 74 4f 4f 56 38 57 37 4c 58 7e 5a 78 7e 31 70 44 52 72 69 66 78 36 32 70 79 71 74 42 2a 68 4b 51 31 39 33 37 7b 6a 23 7a 59 66 6c } //1 6u0CHm87msHhdX|z7cJGr0O0{L?yv?tOOV8W7LX~Zx~1pDRrifx62pyqtB*hKQ1937{j#zYfl
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_81_2  & 1)*1) >=1
 
}