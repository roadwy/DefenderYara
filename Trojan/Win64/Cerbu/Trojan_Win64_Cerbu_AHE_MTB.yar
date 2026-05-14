
rule Trojan_Win64_Cerbu_AHE_MTB{
	meta:
		description = "Trojan:Win64/Cerbu.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b c1 48 c1 e8 ?? 48 33 c1 48 b9 ?? ?? ?? ?? ?? ?? ?? ?? 48 0f af c8 48 03 ca 48 89 8c d4 b8 02 00 00 49 03 d5 48 3b d7 72 } //30
		$a_81_1 = {47 6c 6f 62 61 6c 5c 53 79 73 74 65 6d 49 6e 66 6f 4d 75 74 65 78 } //20 Global\SystemInfoMutex
		$a_01_2 = {42 72 61 76 65 53 6f 66 74 77 61 72 65 5c 42 72 61 76 65 2d 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 } //10 BraveSoftware\Brave-Browser\User Data
	condition:
		((#a_03_0  & 1)*30+(#a_81_1  & 1)*20+(#a_01_2  & 1)*10) >=60
 
}