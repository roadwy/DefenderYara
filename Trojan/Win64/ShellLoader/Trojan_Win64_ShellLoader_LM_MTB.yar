
rule Trojan_Win64_ShellLoader_LM_MTB{
	meta:
		description = "Trojan:Win64/ShellLoader.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 f3 34 88 18 48 8d 40 01 0f b6 18 84 db } //20
		$a_01_1 = {90 b3 67 c7 45 97 67 5b 52 40 c7 45 9b 43 55 46 51 c7 45 9f 68 68 70 51 c7 45 a3 51 44 67 51 66 c7 45 a7 46 00 44 8b cf } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}