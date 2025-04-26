
rule Trojan_Win32_NSISInject_RD_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 ab aa aa aa f7 e1 c1 ea 03 8d 14 52 03 d2 03 d2 8b c1 2b c2 8a ?? ?? ?? ?? ?? 30 14 0e 41 3b cf 72 dd } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_NSISInject_RD_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 ab aa aa aa f7 e6 8b c6 c1 ea 03 8d 0c 52 c1 e1 02 2b c1 8a 80 ?? ?? ?? ?? 30 04 1e 46 3b f7 72 de } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_NSISInject_RD_MTB_3{
	meta:
		description = "Trojan:Win32/NSISInject.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 79 6b 6b 65 72 65 5c 55 6e 69 6e 73 74 61 6c 6c 5c 6a 6f 73 69 61 73 73 } //2 dykkere\Uninstall\josiass
		$a_01_1 = {6d 61 6e 69 66 65 73 74 61 74 69 6f 6e 65 72 5c 62 65 74 76 69 76 6c 65 2e 69 6e 69 } //1 manifestationer\betvivle.ini
		$a_01_2 = {5c 4b 75 6c 74 75 72 66 6f 72 73 6b 65 6c 6c 65 5c 70 72 6f 67 72 61 6d 6d 72 2e 69 6e 69 } //1 \Kulturforskelle\programmr.ini
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule Trojan_Win32_NSISInject_RD_MTB_4{
	meta:
		description = "Trojan:Win32/NSISInject.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 c0 c7 04 24 00 00 00 00 c7 44 24 04 00 09 3d 00 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 ff 15 [0-35] 83 7d f4 00 0f 84 1d 00 00 00 8b 45 ec c6 00 00 8b 45 ec 83 c0 01 89 45 ec 8b 45 f4 83 c0 ff 89 45 f4 e9 d9 ff ff ff 8b 45 10 31 c9 89 04 24 c7 44 24 04 00 00 00 80 c7 44 24 08 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_NSISInject_RD_MTB_5{
	meta:
		description = "Trojan:Win32/NSISInject.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 64 6f 77 73 5c 46 6f 74 6f 65 72 6e 65 73 5c 55 6e 69 6e 73 74 61 6c 6c 5c 49 6e 68 61 6c 61 74 6f 72 65 6e 32 32 34 } //2 Windows\Fotoernes\Uninstall\Inhalatoren224
		$a_01_1 = {46 61 72 76 65 62 61 61 6e 64 73 6f 6d 73 6b 69 66 74 65 72 65 6e 2e 74 78 74 } //1 Farvebaandsomskifteren.txt
		$a_01_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 63 61 6d 65 6c 68 61 69 72 2e 75 64 67 } //1 Application Data\camelhair.udg
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule Trojan_Win32_NSISInject_RD_MTB_6{
	meta:
		description = "Trojan:Win32/NSISInject.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {47 61 72 64 65 6e 6d 61 6b 69 6e 67 2e 6c 6e 6b } //1 Gardenmaking.lnk
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 55 6e 67 64 6f 6d 73 73 65 6b 74 69 6f 6e 65 72 } //1 Software\Ungdomssektioner
		$a_01_2 = {54 61 6b 69 73 74 6f 73 6b 6f 70 73 32 33 30 2e 6c 6e 6b } //1 Takistoskops230.lnk
		$a_01_3 = {43 68 65 6c 61 74 69 6f 6e 73 2e 69 6e 69 } //1 Chelations.ini
		$a_01_4 = {55 6e 69 6e 73 74 61 6c 6c 5c 4f 76 65 72 68 61 6e 67 73 } //1 Uninstall\Overhangs
		$a_01_5 = {41 70 70 65 74 69 74 6c 73 65 73 74 65 73 2e 64 6c 6c } //1 Appetitlsestes.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_Win32_NSISInject_RD_MTB_7{
	meta:
		description = "Trojan:Win32/NSISInject.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 50 00 6c 00 61 00 64 00 72 00 65 00 6e 00 64 00 65 00 } //1 Software\Pladrende
		$a_01_1 = {50 00 72 00 65 00 61 00 73 00 73 00 69 00 67 00 6e 00 73 00 2e 00 69 00 6e 00 69 00 } //1 Preassigns.ini
		$a_01_2 = {41 00 6e 00 74 00 69 00 6d 00 65 00 6e 00 73 00 69 00 75 00 6d 00 2e 00 64 00 6c 00 6c 00 } //1 Antimensium.dll
		$a_01_3 = {41 00 6e 00 65 00 6e 00 63 00 65 00 70 00 68 00 61 00 6c 00 69 00 61 00 2e 00 69 00 6e 00 69 00 } //1 Anencephalia.ini
		$a_01_4 = {55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5c 00 42 00 6c 00 6f 00 64 00 72 00 69 00 67 00 74 00 } //1 Uninstall\Blodrigt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}