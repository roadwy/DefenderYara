
rule Trojan_Win64_NetLoader_ARA_MTB{
	meta:
		description = "Trojan:Win64/NetLoader.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 22 4d 69 63 72 6f 73 6f 66 74 45 64 67 65 55 70 64 61 74 65 53 65 63 75 72 69 74 79 43 6f 72 65 73 22 20 2f 74 72 } //2 schtasks /create /tn "MicrosoftEdgeUpdateSecurityCores" /tr
		$a_01_1 = {2f 73 63 20 6d 69 6e 75 74 65 20 2f 6d 6f 20 31 20 2f 72 75 20 22 53 59 53 54 45 4d 22 20 2f 46 } //3 /sc minute /mo 1 /ru "SYSTEM" /F
		$a_01_2 = {2f 73 63 20 6d 69 6e 75 74 65 20 2f 6d 6f 20 31 20 2f 52 4c 20 48 49 47 48 45 53 54 } //3 /sc minute /mo 1 /RL HIGHEST
		$a_01_3 = {5c 57 69 6e 64 6f 77 53 65 63 75 72 69 74 79 55 70 64 61 74 65 73 5c } //2 \WindowSecurityUpdates\
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2) >=7
 
}