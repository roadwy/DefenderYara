
rule TrojanDropper_Win32_Livuto_gen_A{
	meta:
		description = "TrojanDropper:Win32/Livuto.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {88 10 72 e4 33 c9 0f b6 91 90 01 04 8d 81 90 01 04 41 8a 94 15 90 01 03 ff 83 f9 90 00 } //1
		$a_03_1 = {6a 07 33 ff 99 59 f7 f9 8b f2 83 c6 04 85 f6 7e 0d e8 90 01 04 88 04 1f 47 3b fe 7c f3 90 00 } //1
		$a_03_2 = {ff 51 1c 85 c0 75 5d 8b 45 fc 50 8b 08 ff 51 14 8b 45 fc 8d 55 90 01 01 52 8d 55 90 01 01 8b 08 52 6a 01 50 ff 51 0c 85 c0 75 3d 90 00 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}