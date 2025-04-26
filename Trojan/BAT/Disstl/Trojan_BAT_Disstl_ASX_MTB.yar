
rule Trojan_BAT_Disstl_ASX_MTB{
	meta:
		description = "Trojan:BAT/Disstl.ASX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 "
		
	strings :
		$a_80_0 = {61 70 70 2d 5c 64 5c 2e 5c 64 7b 31 2c 7d 5c 2e 5c 64 7b 31 2c 7d } //app-\d\.\d{1,}\.\d{1,}  3
		$a_80_1 = {64 69 73 63 6f 72 64 5f 64 65 73 6b 74 6f 70 5f 63 6f 72 65 } //discord_desktop_core  3
		$a_80_2 = {64 69 73 61 62 6c 65 5f 32 66 61 } //disable_2fa  3
		$a_80_3 = {2d 2d 70 72 6f 63 65 73 73 53 74 61 72 74 } //--processStart  3
		$a_80_4 = {43 68 65 63 6b 54 6f 6b 65 6e 73 } //CheckTokens  3
		$a_80_5 = {28 5c 77 7c 5c 64 29 7b 32 34 7d 5c 2e 28 5c 77 7c 5c 64 7c 5f 7c 2d 29 7b 36 7d 2e 28 5c 77 7c 5c 64 7c 5f 7c 2d 29 7b 32 37 7d } //(\w|\d){24}\.(\w|\d|_|-){6}.(\w|\d|_|-){27}  3
		$a_80_6 = {77 65 62 68 6f 6f 6b } //webhook  3
		$a_80_7 = {50 6f 73 74 41 73 79 6e 63 } //PostAsync  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=24
 
}