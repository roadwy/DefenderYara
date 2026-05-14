
rule Trojan_BAT_Injector_AH_MTB{
	meta:
		description = "Trojan:BAT/Injector.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_81_0 = {43 61 6e 74 20 43 72 65 61 74 65 20 50 72 6f 63 65 73 73 2e 2e 21 } //30 Cant Create Process..!
		$a_01_1 = {24 66 33 38 32 38 30 63 62 2d 30 35 31 39 2d 34 32 63 32 2d 61 32 38 33 2d 34 37 37 35 34 35 33 63 61 62 63 63 } //20 $f38280cb-0519-42c2-a283-4775453cabcc
	condition:
		((#a_81_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}
rule Trojan_BAT_Injector_AH_MTB_2{
	meta:
		description = "Trojan:BAT/Injector.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 36 1e 1f 2e 9c 11 36 1f 09 1f 64 9c 11 36 1f 0a 1f 6c 9c 11 36 1f 0b 1f 6c 9c 11 36 } //20
		$a_03_1 = {11 2a 20 00 30 00 00 1a 6f ?? ?? ?? 06 13 24 11 24 16 33 06 73 ?? ?? ?? 0a 7a 11 1c 12 09 7b ?? ?? ?? 04 11 24 04 11 29 12 0c 6f ?? ?? ?? 06 } //30
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*30) >=50
 
}