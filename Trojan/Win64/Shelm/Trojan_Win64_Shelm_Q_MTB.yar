
rule Trojan_Win64_Shelm_Q_MTB{
	meta:
		description = "Trojan:Win64/Shelm.Q!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 95 c4 44 87 e2 41 55 88 de 66 44 0f b6 e9 4c 8d 24 65 ?? ?? ?? ?? 41 53 66 45 87 ec 4c 0f b6 eb f3 9c } //2
		$a_01_1 = {4c 0f be e9 66 41 f7 d4 41 50 66 0f bb ff f8 0f 95 c3 66 0f b6 c2 41 56 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}