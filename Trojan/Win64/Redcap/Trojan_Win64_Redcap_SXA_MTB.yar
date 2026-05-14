
rule Trojan_Win64_Redcap_SXA_MTB{
	meta:
		description = "Trojan:Win64/Redcap.SXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 07 00 00 "
		
	strings :
		$a_80_0 = {4e 65 78 4c 6f 61 64 65 72 20 55 49 20 43 6c 61 73 73 } //NexLoader UI Class  20
		$a_01_1 = {4e 65 78 4c 6f 61 64 65 72 5f 4d 61 69 6e } //20 NexLoader_Main
		$a_80_2 = {63 6d 64 2e 65 78 65 20 2f 63 20 22 74 69 6d 65 6f 75 74 20 2f 74 20 31 20 26 26 20 64 65 6c 20 2f 66 20 2f 71 20 } //cmd.exe /c "timeout /t 1 && del /f /q   10
		$a_80_3 = {2d 2d 6d 75 74 61 74 65 64 } //--mutated  4
		$a_01_4 = {4c 61 75 6e 63 68 20 43 6c 69 65 6e 74 } //2 Launch Client
		$a_01_5 = {49 6e 6a 65 63 74 20 49 6e 74 65 72 6e 61 6c } //2 Inject Internal
		$a_01_6 = {53 70 6f 6f 66 20 48 61 72 64 77 61 72 65 } //2 Spoof Hardware
	condition:
		((#a_80_0  & 1)*20+(#a_01_1  & 1)*20+(#a_80_2  & 1)*10+(#a_80_3  & 1)*4+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=60
 
}