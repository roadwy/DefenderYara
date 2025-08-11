
rule Trojan_Win32_ClickFix_BSA_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.BSA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0f 00 0f 00 04 00 00 "
		
	strings :
		$a_00_0 = {65 00 6e 00 76 00 3a 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 } //2 env:AppData
		$a_00_1 = {63 00 75 00 72 00 6c 00 } //1 curl
		$a_00_2 = {6c 00 75 00 63 00 6b 00 79 00 73 00 65 00 61 00 77 00 6f 00 72 00 6c 00 64 00 2e 00 63 00 6f 00 6d 00 2f 00 6e 00 6f 00 77 00 2e 00 6d 00 73 00 69 00 } //10 luckyseaworld.com/now.msi
		$a_00_3 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 20 00 2f 00 69 00 } //2 msiexec.exe /i
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*10+(#a_00_3  & 1)*2) >=15
 
}