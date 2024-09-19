
rule Trojan_Win32_Relatsnif_A{
	meta:
		description = "Trojan:Win32/Relatsnif.A,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {63 00 75 00 72 00 6c 00 [0-10] 20 00 2d 00 6f 00 20 00 } //2
		$a_00_1 = {63 00 75 00 72 00 73 00 65 00 2d 00 62 00 72 00 65 00 61 00 6b 00 65 00 72 00 2e 00 6f 00 72 00 67 00 } //2 curse-breaker.org
		$a_00_2 = {66 00 69 00 6c 00 65 00 73 00 2f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 2e 00 64 00 6c 00 6c 00 } //1 files/installer.dll
		$a_00_3 = {5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 52 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 5c 00 49 00 46 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 2e 00 64 00 6c 00 6c 00 } //1 \AppData\Roaming\IFInstaller.dll
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}