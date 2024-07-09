
rule Backdoor_Win32_Zegost_BZ{
	meta:
		description = "Backdoor:Win32/Zegost.BZ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_00_0 = {00 5b 63 61 70 73 6c 6f 63 6b 5d 00 } //1 嬀慣獰潬正]
		$a_00_1 = {77 69 6e 73 74 61 30 5c 64 65 66 61 75 6c 74 } //1 winsta0\default
		$a_00_2 = {66 64 65 6e 79 74 73 63 6f 6e 6e 65 63 74 69 6f 6e 73 } //1 fdenytsconnections
		$a_00_3 = {68 74 74 70 2f 31 2e 31 20 34 30 33 20 66 6f 72 62 69 64 64 65 6e } //1 http/1.1 403 forbidden
		$a_00_4 = {25 73 20 73 70 25 64 00 32 30 31 32 } //1 猥猠╰d〲㈱
		$a_00_5 = {72 64 70 77 64 5c 54 64 73 5c 74 63 70 } //1 rdpwd\Tds\tcp
		$a_00_6 = {70 62 6b 5c 72 61 73 70 68 6f 6e 65 2e 70 62 6b } //1 pbk\rasphone.pbk
		$a_03_7 = {ff 53 c6 85 ?? ?? ff ff 4f c6 85 ?? ?? ff ff 46 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_03_7  & 1)*1) >=5
 
}