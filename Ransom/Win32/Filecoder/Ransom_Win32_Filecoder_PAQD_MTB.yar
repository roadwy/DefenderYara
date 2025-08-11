
rule Ransom_Win32_Filecoder_PAQD_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.PAQD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 c1 e0 08 89 c2 8b 45 f0 01 d0 8b 14 85 ?? ?? ?? ?? 8b 45 14 8b 4d f4 89 cb c1 e3 08 8b 4d f0 01 d9 89 14 88 83 45 f0 01 81 7d f0 ff } //3
		$a_01_1 = {8b 45 f4 ba 00 00 00 00 f7 75 f0 89 d0 8b 44 85 b4 31 c1 8b 45 14 8b 55 f4 81 c2 00 04 00 00 89 0c 90 83 45 f4 01 83 7d f4 11 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}