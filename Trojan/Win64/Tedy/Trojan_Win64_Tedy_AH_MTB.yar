
rule Trojan_Win64_Tedy_AH_MTB{
	meta:
		description = "Trojan:Win64/Tedy.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {32 db 48 8b 54 24 58 48 83 fa 07 0f 86 c1 00 00 00 48 8b 4c 24 40 48 8d 14 55 02 00 00 00 48 8b c1 48 81 fa 00 10 00 00 0f 82 9f 00 00 00 48 8b 49 f8 } //1
		$a_01_1 = {56 69 78 65 6e 2e 65 78 65 } //1 Vixen.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win64_Tedy_AH_MTB_2{
	meta:
		description = "Trojan:Win64/Tedy.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 48 0f 7e f7 66 0f 73 de ?? 66 49 0f 7e f7 4c 8d 74 24 78 66 48 0f 7e fe 49 83 ff ?? 4c 0f 47 f6 } //20
		$a_03_1 = {44 8b c0 41 81 f0 ?? ?? ?? ?? 41 c1 c8 ?? 8b d0 81 f2 ?? ?? ?? ?? c1 ca ?? 8b c8 81 f1 ?? ?? ?? ?? c1 c9 ?? 35 ?? ?? ?? ?? c1 c8 ?? 44 89 44 24 30 } //30
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*30) >=50
 
}