
rule TrojanDropper_Win64_Lazy_AH_MTB{
	meta:
		description = "TrojanDropper:Win64/Lazy.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 67 72 61 6d 44 61 74 61 5c 52 6f 6e 69 6e 67 5c 74 72 75 73 74 69 6e 73 74 61 6c 6c 65 72 2e 62 69 6e } //10 ProgramData\Roning\trustinstaller.bin
		$a_01_1 = {74 5e 61 5e 73 5e 6b 5e 6c 5e 69 5e 73 5e 74 20 20 20 20 20 2f 66 69 20 20 20 20 22 50 49 44 20 20 65 71 } //20 t^a^s^k^l^i^s^t     /fi    "PID  eq
		$a_01_2 = {4d 69 63 72 6f 73 6f 66 74 31 45 64 67 65 32 45 6c 65 76 61 74 69 6f 6e 33 53 65 72 76 69 63 65 34 } //30 Microsoft1Edge2Elevation3Service4
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20+(#a_01_2  & 1)*30) >=60
 
}