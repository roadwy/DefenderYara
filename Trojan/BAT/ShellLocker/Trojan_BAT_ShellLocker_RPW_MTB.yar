
rule Trojan_BAT_ShellLocker_RPW_MTB{
	meta:
		description = "Trojan:BAT/ShellLocker.RPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {65 00 61 00 73 00 79 00 65 00 78 00 70 00 6c 00 6f 00 69 00 74 00 73 00 2e 00 63 00 6f 00 6d 00 } //1 easyexploits.com
		$a_01_1 = {46 00 75 00 72 00 6b 00 42 00 79 00 74 00 65 00 43 00 6f 00 64 00 65 00 2e 00 64 00 6c 00 6c 00 } //1 FurkByteCode.dll
		$a_01_2 = {69 00 73 00 20 00 69 00 6e 00 6a 00 65 00 63 00 74 00 69 00 6e 00 67 00 2e 00 2e 00 2e 00 } //1 is injecting...
		$a_01_3 = {66 00 61 00 73 00 68 00 69 00 6f 00 6e 00 61 00 62 00 6c 00 65 00 67 00 61 00 6e 00 67 00 73 00 74 00 65 00 72 00 65 00 78 00 70 00 6c 00 6f 00 73 00 69 00 6f 00 6e 00 2e 00 63 00 6f 00 6d 00 } //1 fashionablegangsterexplosion.com
		$a_01_4 = {69 00 6e 00 69 00 65 00 61 00 73 00 79 00 2e 00 6c 00 75 00 61 00 } //1 inieasy.lua
		$a_01_5 = {4c 00 6f 00 61 00 64 00 4c 00 69 00 62 00 72 00 61 00 72 00 79 00 41 00 } //1 LoadLibraryA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}