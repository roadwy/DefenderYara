
rule Trojan_Win32_NSISInject_RD_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 ab aa aa aa f7 e1 c1 ea 03 8d 14 52 03 d2 03 d2 8b c1 2b c2 8a 90 01 05 30 14 0e 41 3b cf 72 dd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RD_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 ab aa aa aa f7 e6 8b c6 c1 ea 03 8d 0c 52 c1 e1 02 2b c1 8a 80 90 01 04 30 04 1e 46 3b f7 72 de 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RD_MTB_3{
	meta:
		description = "Trojan:Win32/NSISInject.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 c0 c7 04 24 00 00 00 00 c7 44 24 04 00 09 3d 00 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 ff 15 90 02 35 83 7d f4 00 0f 84 1d 00 00 00 8b 45 ec c6 00 00 8b 45 ec 83 c0 01 89 45 ec 8b 45 f4 83 c0 ff 89 45 f4 e9 d9 ff ff ff 8b 45 10 31 c9 89 04 24 c7 44 24 04 00 00 00 80 c7 44 24 08 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RD_MTB_4{
	meta:
		description = "Trojan:Win32/NSISInject.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 61 72 64 65 6e 6d 61 6b 69 6e 67 2e 6c 6e 6b } //01 00  Gardenmaking.lnk
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 55 6e 67 64 6f 6d 73 73 65 6b 74 69 6f 6e 65 72 } //01 00  Software\Ungdomssektioner
		$a_01_2 = {54 61 6b 69 73 74 6f 73 6b 6f 70 73 32 33 30 2e 6c 6e 6b } //01 00  Takistoskops230.lnk
		$a_01_3 = {43 68 65 6c 61 74 69 6f 6e 73 2e 69 6e 69 } //01 00  Chelations.ini
		$a_01_4 = {55 6e 69 6e 73 74 61 6c 6c 5c 4f 76 65 72 68 61 6e 67 73 } //01 00  Uninstall\Overhangs
		$a_01_5 = {41 70 70 65 74 69 74 6c 73 65 73 74 65 73 2e 64 6c 6c } //00 00  Appetitlsestes.dll
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RD_MTB_5{
	meta:
		description = "Trojan:Win32/NSISInject.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 50 00 6c 00 61 00 64 00 72 00 65 00 6e 00 64 00 65 00 } //01 00  Software\Pladrende
		$a_01_1 = {50 00 72 00 65 00 61 00 73 00 73 00 69 00 67 00 6e 00 73 00 2e 00 69 00 6e 00 69 00 } //01 00  Preassigns.ini
		$a_01_2 = {41 00 6e 00 74 00 69 00 6d 00 65 00 6e 00 73 00 69 00 75 00 6d 00 2e 00 64 00 6c 00 6c 00 } //01 00  Antimensium.dll
		$a_01_3 = {41 00 6e 00 65 00 6e 00 63 00 65 00 70 00 68 00 61 00 6c 00 69 00 61 00 2e 00 69 00 6e 00 69 00 } //01 00  Anencephalia.ini
		$a_01_4 = {55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5c 00 42 00 6c 00 6f 00 64 00 72 00 69 00 67 00 74 00 } //00 00  Uninstall\Blodrigt
	condition:
		any of ($a_*)
 
}