
rule VirTool_BAT_CryptInject_PG_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.PG!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {5c 00 73 00 63 00 72 00 65 00 65 00 6e 00 73 00 68 00 6f 00 74 00 2e 00 6a 00 70 00 67 00 } //1 \screenshot.jpg
		$a_01_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 61 00 70 00 69 00 2e 00 69 00 70 00 69 00 66 00 79 00 2e 00 6f 00 72 00 67 00 } //1 https://api.ipify.org
		$a_01_2 = {42 65 64 73 2d 50 72 6f 74 65 63 74 6f 72 2d 54 68 65 2d 51 75 69 63 6b 2d 42 72 6f 77 6e 2d 46 6f 78 2d 4a 75 6d 70 65 64 2d 4f 76 65 72 2d 54 68 65 2d 4c 61 7a 79 2d 44 6f 67 } //1 Beds-Protector-The-Quick-Brown-Fox-Jumped-Over-The-Lazy-Dog
		$a_01_3 = {53 00 74 00 65 00 61 00 6c 00 65 00 72 00 5f 00 62 00 75 00 69 00 6c 00 64 00 2e 00 65 00 78 00 65 00 } //1 Stealer_build.exe
		$a_01_4 = {5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 33 00 32 00 2e 00 74 00 78 00 74 00 } //1 \Chrome32.txt
		$a_01_5 = {68 74 74 70 3a 2f 2f 67 6f 6f 2e 67 6c 2f 59 72 6f 5a 6d } //1 http://goo.gl/YroZm
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}