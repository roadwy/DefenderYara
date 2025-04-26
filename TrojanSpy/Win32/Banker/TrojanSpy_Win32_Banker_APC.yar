
rule TrojanSpy_Win32_Banker_APC{
	meta:
		description = "TrojanSpy:Win32/Banker.APC,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 45 f0 01 00 00 00 8b 45 e4 8b 55 f0 0f b7 44 50 fe 33 45 dc 89 45 d8 8b 45 d8 3b 45 ec 7f 10 8b 45 d8 05 ff 00 00 00 2b 45 ec 89 45 d8 eb 06 } //3
		$a_01_1 = {49 00 54 00 41 00 43 00 4f 00 44 00 49 00 47 00 4f 00 7c 00 00 00 } //1
		$a_01_2 = {54 00 46 00 49 00 54 00 41 00 4c 00 49 00 45 00 } //1 TFITALIE
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}