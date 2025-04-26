
rule Trojan_Win32_Stealgen_GA_MTB{
	meta:
		description = "Trojan:Win32/Stealgen.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0e 00 00 "
		
	strings :
		$a_80_0 = {41 6e 74 69 56 4d } //AntiVM  1
		$a_80_1 = {41 6e 74 69 53 61 6e 64 42 6f 78 69 65 } //AntiSandBoxie  1
		$a_80_2 = {53 62 69 65 44 6c 6c 2e 64 6c 6c } //SbieDll.dll  1
		$a_80_3 = {76 6d 77 61 72 65 } //vmware  1
		$a_80_4 = {64 65 74 65 63 74 65 64 } //detected  1
		$a_80_5 = {44 69 73 63 6f 72 64 } //Discord  1
		$a_80_6 = {3c 70 61 73 73 77 6f 72 64 3e } //<password>  1
		$a_80_7 = {3c 63 68 61 6e 6e 65 6c } //<channel  1
		$a_80_8 = {47 72 61 62 62 65 72 } //Grabber  1
		$a_80_9 = {50 72 6f 63 65 73 73 4b 69 6c 6c } //ProcessKill  1
		$a_80_10 = {52 6f 62 6c 6f 78 43 6f 6f 6b 69 65 73 } //RobloxCookies  1
		$a_80_11 = {53 45 4c 45 43 54 20 6e 61 6d 65 2c 76 61 6c 75 65 2c 68 6f 73 74 20 46 52 4f 4d 20 6d 6f 7a 5f 63 6f 6f 6b 69 65 73 } //SELECT name,value,host FROM moz_cookies  1
		$a_80_12 = {6e 61 6d 65 3d 22 70 61 79 6c 6f 61 64 5f 6a 73 6f 6e 22 } //name="payload_json"  1
		$a_80_13 = {68 74 74 70 73 3a 2f 2f 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 70 69 2f 76 7b 30 7d } //https://discordapp.com/api/v{0}  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1) >=11
 
}