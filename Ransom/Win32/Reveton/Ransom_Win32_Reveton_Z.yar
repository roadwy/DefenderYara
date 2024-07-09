
rule Ransom_Win32_Reveton_Z{
	meta:
		description = "Ransom:Win32/Reveton.Z,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 55 fc 0f b6 54 1a ff 66 81 f2 9a 02 88 54 18 ff 43 4e 75 e3 } //10
		$a_01_1 = {57 41 4c 4c 45 54 2e 44 41 54 00 00 ff ff ff ff 09 00 00 00 42 4c 41 43 4b 43 4f 49 4e } //1
		$a_03_2 = {2c 01 00 00 6a 00 6a 04 8d 45 ?? 50 53 e8 ?? ?? ?? ?? 40 0f 84 90 09 03 00 c7 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_03_2  & 1)*10) >=21
 
}