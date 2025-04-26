
rule Ransom_Win32_QuantumLocker_AB{
	meta:
		description = "Ransom:Win32/QuantumLocker.AB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {66 8b 45 fc 66 83 c0 01 66 89 45 fc 0f b7 45 fc 0f b7 4d f8 3b c1 7d 29 ff 75 f4 e8 ?? ?? ?? ?? 59 89 45 f4 0f b7 45 fc 8b 4d 08 0f b6 04 01 0f b6 4d f4 33 c1 0f b7 4d fc 8b 55 0c 88 04 0a eb bf } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10) >=11
 
}