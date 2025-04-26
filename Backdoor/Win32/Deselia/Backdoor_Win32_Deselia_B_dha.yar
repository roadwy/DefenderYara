
rule Backdoor_Win32_Deselia_B_dha{
	meta:
		description = "Backdoor:Win32/Deselia.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {4c 6f 61 64 65 72 44 4c 4c 2e 64 6c 6c 00 } //1 潌摡牥䱄⹌汤l
		$a_01_1 = {00 53 65 74 74 69 6e 67 00 55 70 64 61 74 65 00 } //1 匀瑥楴杮唀摰瑡e
		$a_01_2 = {0f b6 01 8d 49 fe 30 41 03 0f b6 41 01 30 41 02 4a 75 ed } //1
		$a_03_3 = {8a 4c 30 ff 30 0c 30 48 85 c0 7f f4 80 36 ?? 5e } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}