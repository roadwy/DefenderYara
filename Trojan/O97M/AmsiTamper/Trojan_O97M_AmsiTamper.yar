
rule Trojan_O97M_AmsiTamper{
	meta:
		description = "Trojan:O97M/AmsiTamper,SIGNATURE_TYPE_MACROHSTR_EXT,0f 00 0f 00 07 00 00 "
		
	strings :
		$a_00_0 = {22 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 53 63 72 69 70 74 5c 53 65 74 74 69 6e 67 73 5c 41 6d 73 69 45 6e 61 62 6c 65 22 } //5 "HKCU\Software\Microsoft\Windows Script\Settings\AmsiEnable"
		$a_00_1 = {47 65 74 4f 62 6a 65 63 74 28 22 6e 65 77 3a 37 32 43 32 34 44 44 35 2d 44 37 30 41 2d 34 33 38 42 2d 38 41 34 32 2d 39 38 34 32 34 42 38 38 41 46 42 38 22 29 } //5 GetObject("new:72C24DD5-D70A-438B-8A42-98424B88AFB8")
		$a_00_2 = {2e 52 65 67 57 72 69 74 65 20 72 65 67 70 61 74 68 2c 20 22 30 22 2c 20 22 52 45 47 5f 44 57 4f 52 44 22 } //1 .RegWrite regpath, "0", "REG_DWORD"
		$a_00_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 44 4f 4d 22 29 } //1 CreateObject("Microsoft.XMLDOM")
		$a_00_4 = {2e 61 73 79 6e 63 20 3d 20 46 61 6c 73 65 } //1 .async = False
		$a_02_5 = {2e 4c 6f 61 64 20 22 68 74 74 70 3a 2f 2f [0-60] 2f [0-10] 2e 78 73 6c 22 } //1
		$a_00_6 = {2e 74 72 61 6e 73 66 6f 72 6d 4e 6f 64 65 } //1 .transformNode
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_02_5  & 1)*1+(#a_00_6  & 1)*1) >=15
 
}