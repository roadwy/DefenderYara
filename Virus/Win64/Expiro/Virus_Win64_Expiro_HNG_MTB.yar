
rule Virus_Win64_Expiro_HNG_MTB{
	meta:
		description = "Virus:Win64/Expiro.HNG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 28 e8 ?? ?? ?? ?? 48 83 c4 28 e9 } //10
		$a_03_1 = {2e 74 65 78 74 00 00 00 [0-e8] 2e 72 65 6c 6f 63 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 40 00 00 e2 } //1
		$a_03_2 = {2e 74 65 78 74 00 00 00 [0-e8] 2e 72 65 6c 6f 63 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 40 00 00 60 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=11
 
}