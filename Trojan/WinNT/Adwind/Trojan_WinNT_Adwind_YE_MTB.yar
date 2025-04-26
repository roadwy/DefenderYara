
rule Trojan_WinNT_Adwind_YE_MTB{
	meta:
		description = "Trojan:WinNT/Adwind.YE!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 6c 69 6e 65 2e 73 6d 61 72 74 69 6e 74 65 72 61 63 74 69 76 65 74 65 63 68 2e 63 6f 6d 2f 6e 61 7a 69 6f 6e 61 6c 65 2e 65 78 65 } //1 http://line.smartinteractivetech.com/nazionale.exe
		$a_00_1 = {72 75 6e 64 6c 6c 33 32 20 75 72 6c 2e 64 6c 6c 2c 46 69 6c 65 50 72 6f 74 6f 63 6f 6c 48 61 6e 64 6c 65 72 } //1 rundll32 url.dll,FileProtocolHandler
		$a_00_2 = {66 72 69 73 63 6f 34 31 35 } //1 frisco415
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}