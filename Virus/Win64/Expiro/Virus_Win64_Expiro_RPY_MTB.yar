
rule Virus_Win64_Expiro_RPY_MTB{
	meta:
		description = "Virus:Win64/Expiro.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f7 90 a8 00 00 00 f7 90 e4 00 00 00 f7 90 54 02 00 00 f7 50 50 f7 90 88 00 00 00 } //1
		$a_03_1 = {48 81 c7 00 04 00 00 48 81 c0 00 04 00 00 48 81 ff 00 c0 08 00 74 05 e9 ?? ?? ff ff 59 e8 ?? ?? ff ff 48 8b e5 5d 41 5f 41 5e 41 5d 41 5c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}