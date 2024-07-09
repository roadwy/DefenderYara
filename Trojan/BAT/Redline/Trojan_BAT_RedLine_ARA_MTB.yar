
rule Trojan_BAT_RedLine_ARA_MTB{
	meta:
		description = "Trojan:BAT/RedLine.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_80_0 = {5c 43 6f 6f 6b 69 65 73 5f 4d 6f 7a 69 6c 6c 61 2e 74 78 74 } //\Cookies_Mozilla.txt  2
		$a_80_1 = {5c 50 61 73 73 77 6f 72 64 73 5f 4d 6f 7a 69 6c 6c 61 2e 74 78 74 } //\Passwords_Mozilla.txt  2
		$a_80_2 = {77 69 6e 33 32 5f 6c 6f 67 69 63 61 6c 64 69 73 6b 2e 64 65 76 69 63 65 69 64 3d 22 } //win32_logicaldisk.deviceid="  2
		$a_03_3 = {07 06 08 1f 0a 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 05 12 05 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 11 04 17 58 13 04 11 04 09 fe 04 13 06 11 06 2d cb } //2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_03_3  & 1)*2) >=8
 
}