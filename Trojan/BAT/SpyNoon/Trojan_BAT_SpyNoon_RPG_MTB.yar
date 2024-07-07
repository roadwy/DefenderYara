
rule Trojan_BAT_SpyNoon_RPG_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {6c 00 6f 00 63 00 6b 00 77 00 6f 00 6f 00 64 00 2e 00 72 00 66 00 2e 00 67 00 64 00 } //1 lockwood.rf.gd
		$a_01_1 = {45 00 4e 00 43 00 2e 00 74 00 78 00 74 00 } //1 ENC.txt
		$a_01_2 = {45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 } //1 EntryPoint
		$a_01_3 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //1 Invoke
		$a_01_4 = {48 42 61 6e 6b 65 72 73 } //1 HBankers
		$a_01_5 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
		$a_01_6 = {4c 61 74 65 47 65 74 } //1 LateGet
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}