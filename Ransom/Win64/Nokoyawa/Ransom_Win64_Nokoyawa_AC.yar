
rule Ransom_Win64_Nokoyawa_AC{
	meta:
		description = "Ransom:Win64/Nokoyawa.AC,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {48 83 ec 28 48 83 3d ?? ?? ?? ?? 00 75 14 48 8d 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 83 3d ?? ?? ?? ?? 00 75 1b 48 8d 15 ?? ?? ?? ?? 48 8b 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 41 b9 02 00 00 00 44 8b 44 24 ?? 48 8b 54 24 ?? 33 c9 ff 15 ?? ?? ?? ?? 48 83 c4 28 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10) >=11
 
}