
rule Trojan_Win32_Blackmoon_PPDW_MTB{
	meta:
		description = "Trojan:Win32/Blackmoon.PPDW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 20 2f 63 20 65 63 68 6f 20 59 7c 73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 73 63 20 6d 69 6e 75 74 65 20 2f 6d 6f 20 } //cmd /c echo Y|schtasks /create /sc minute /mo   1
		$a_80_1 = {59 67 74 70 58 49 68 4f 4f 6a 72 67 72 6e 45 77 2e 65 78 65 } //YgtpXIhOOjrgrnEw.exe  2
		$a_80_2 = {42 4d 70 5a 77 46 67 4c 69 49 6e 61 66 65 64 75 2e 65 78 65 } //BMpZwFgLiInafedu.exe  1
		$a_80_3 = {64 56 61 61 4f 44 6f 41 71 55 61 65 57 64 63 47 2e 65 78 65 } //dVaaODoAqUaeWdcG.exe  1
		$a_80_4 = {6a 71 4d 66 42 69 65 58 6f 45 55 44 58 41 7a 5a 2e 65 78 65 } //jqMfBieXoEUDXAzZ.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=6
 
}