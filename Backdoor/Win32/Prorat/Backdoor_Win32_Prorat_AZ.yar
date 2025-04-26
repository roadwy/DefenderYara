
rule Backdoor_Win32_Prorat_AZ{
	meta:
		description = "Backdoor:Win32/Prorat.AZ,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 06 00 00 "
		
	strings :
		$a_00_0 = {40 5b 50 72 6f 52 61 74 20 54 72 6f 6a 61 6e 20 48 6f 72 73 65 20 2d 20 43 6f 64 65 64 20 62 79 20 50 52 4f 20 47 72 6f 75 70 20 2d 20 4d 61 64 65 20 69 6e 20 54 75 72 6b 65 79 5d } //1 @[ProRat Trojan Horse - Coded by PRO Group - Made in Turkey]
		$a_00_1 = {6e 63 6f 6d 5f 2e } //1 ncom_.
		$a_00_2 = {6e 63 6f 6d 2e 65 78 65 } //1 ncom.exe
		$a_00_3 = {69 66 20 65 78 69 73 74 20 20 25 63 25 73 25 63 20 67 6f 74 6f 20 31 } //1 if exist  %c%s%c goto 1
		$a_02_4 = {6a 00 52 55 ff 15 ?? ?? ?? ?? 8d 84 24 ?? ?? ?? ?? 50 6a 38 6a 37 6a 69 6a 6e 6a 69 6a 74 6a 6f 6a 66 e8 ?? ?? ?? ?? 8b f8 83 c4 30 8b cf 2b cb 8d 41 f2 85 c0 7e 25 8b d8 55 } //10
		$a_02_5 = {c1 e9 02 8b fa 8d 54 24 ?? f3 a5 8b c8 33 c0 83 e1 03 f3 a4 83 c9 ff bf ?? ?? ?? ?? f2 ae f7 d1 2b f9 8b f7 8b fa 8b d1 83 c9 ff f2 ae 8b ca 4f c1 e9 02 f3 a5 8b ca 8d 44 24 78 83 e1 03 a3 ?? ?? ?? ?? f3 a4 bf ?? ?? ?? ?? 83 c9 ff 33 c0 8d 54 24 ?? f2 ae f7 d1 2b f9 8b f7 8b fa 8b d1 83 c9 ff f2 ae 8b ca 4f c1 e9 02 f3 a5 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*10+(#a_02_5  & 1)*10) >=22
 
}