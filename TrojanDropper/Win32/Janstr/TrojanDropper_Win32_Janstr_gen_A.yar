
rule TrojanDropper_Win32_Janstr_gen_A{
	meta:
		description = "TrojanDropper:Win32/Janstr.gen!A,SIGNATURE_TYPE_PEHSTR,1e 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 81 c4 48 ff ff ff 53 33 c9 89 8d 4c ff ff ff 89 8d 48 ff ff ff 89 8d 50 ff ff ff 89 8d 54 ff ff ff 89 8d 58 ff ff ff 89 4d f0 89 45 fc 33 c0 } //10
		$a_01_1 = {b8 80 ed 44 00 e8 c7 fd ff ff 84 c0 74 2c 8d 95 58 ff ff ff } //10
		$a_01_2 = {55 8b ec 81 c4 b8 fe ff ff 53 56 57 33 d2 89 95 c0 fe ff ff 89 95 b8 fe ff ff 89 95 bc fe ff ff 89 95 d0 fe ff ff 89 95 c4 fe ff ff 89 95 cc fe ff ff 89 95 c8 fe ff ff 89 45 fc 8b 45 fc } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=20
 
}