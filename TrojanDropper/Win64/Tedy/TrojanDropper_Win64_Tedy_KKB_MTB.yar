
rule TrojanDropper_Win64_Tedy_KKB_MTB{
	meta:
		description = "TrojanDropper:Win64/Tedy.KKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 95 98 00 00 00 48 8b 45 48 48 01 d0 0f b6 00 83 f0 c4 89 c2 48 8b 4d 30 48 8b 45 48 48 01 c8 88 10 48 83 45 48 01 } //20
		$a_01_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 6d 73 70 66 2e 65 78 65 } //5 \Microsoft\Windows\mspf.exe
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*5) >=25
 
}