
rule Trojan_BAT_SpyAgent_F_AMTB{
	meta:
		description = "Trojan:BAT/SpyAgent.F!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {47 6c 6f 62 61 6c 5c 52 41 54 5f 48 69 64 64 65 6e 43 6c 69 65 6e 74 5f 76 34 } //Global\RAT_HiddenClient_v4  1
		$a_80_1 = {43 6f 6e 6e 65 63 74 69 6f 6e 20 6c 6f 73 74 20 64 75 72 69 6e 67 20 75 70 6c 6f 61 64 } //Connection lost during upload  1
		$a_80_2 = {4c 6f 73 74 20 64 75 72 69 6e 67 20 77 61 6c 6c 70 61 70 65 72 } //Lost during wallpaper  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}