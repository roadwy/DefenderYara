
rule TrojanDropper_Win64_Tedy_KK_MTB{
	meta:
		description = "TrojanDropper:Win64/Tedy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 45 f8 48 01 d0 0f b6 00 83 f0 27 89 c2 48 ?? ?? ?? ?? ?? ?? 48 8b 45 f8 48 01 c8 88 10 48 83 45 f8 01 } //20
		$a_01_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 6d 73 73 77 2e 65 78 65 } //10 \Microsoft\Windows\mssw.exe
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}