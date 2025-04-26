
rule Trojan_Win32_Viewsure_A_dha{
	meta:
		description = "Trojan:Win32/Viewsure.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {5c 00 52 00 50 00 43 00 20 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 55 00 6d 00 70 00 64 00 50 00 72 00 6f 00 78 00 79 00 5f 00 25 00 78 00 5f 00 25 00 78 00 5f 00 25 00 78 00 5f 00 25 00 78 00 } //1 \RPC Control\UmpdProxy_%x_%x_%x_%x
		$a_00_1 = {77 69 6e 73 70 6f 6f 6c 2e 64 72 76 } //1 winspool.drv
		$a_00_2 = {44 6f 63 75 6d 65 6e 74 45 76 65 6e 74 } //1 DocumentEvent
		$a_00_3 = {68 64 63 43 72 65 61 74 65 44 43 57 } //1 hdcCreateDCW
		$a_80_4 = {4d 69 63 72 6f 73 6f 66 74 20 58 50 53 20 44 6f 63 75 6d 65 6e 74 20 57 72 69 74 65 72 } //Microsoft XPS Document Writer  1
		$a_00_5 = {43 72 65 61 74 65 44 43 2e 65 78 65 } //2 CreateDC.exe
		$a_00_6 = {25 00 73 00 5c 00 50 00 6f 00 50 00 63 00 2e 00 64 00 6c 00 6c 00 } //3 %s\PoPc.dll
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_80_4  & 1)*1+(#a_00_5  & 1)*2+(#a_00_6  & 1)*3) >=5
 
}