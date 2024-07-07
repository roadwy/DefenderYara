
rule Trojan_Win32_Almanahe_B{
	meta:
		description = "Trojan:Win32/Almanahe.B,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_01_0 = {3f 61 63 74 69 6f 6e 3d 70 6f 73 74 26 48 44 3d 25 73 26 4f 54 } //2 ?action=post&HD=%s&OT
		$a_00_1 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //1 \drivers\etc\hosts
		$a_01_2 = {25 73 5c 43 24 5c 73 65 74 75 70 2e 65 78 65 } //1 %s\C$\setup.exe
		$a_01_3 = {25 73 3f 61 63 74 69 6f 6e 3d 75 70 64 61 74 65 26 76 65 72 73 69 6f 6e 3d 25 75 } //2 %s?action=update&version=%u
		$a_00_4 = {68 74 6d 6c 66 69 6c 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 htmlfile\shell\open\command
		$a_01_5 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 25 73 } //2 SYSTEM\CurrentControlSet\Services\%s
		$a_00_6 = {5a 77 4c 6f 61 64 44 72 69 76 65 72 } //2 ZwLoadDriver
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_00_4  & 1)*1+(#a_01_5  & 1)*2+(#a_00_6  & 1)*2) >=10
 
}