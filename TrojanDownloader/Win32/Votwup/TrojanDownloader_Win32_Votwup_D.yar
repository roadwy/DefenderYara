
rule TrojanDownloader_Win32_Votwup_D{
	meta:
		description = "TrojanDownloader:Win32/Votwup.D,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {5a 70 5f 73 74 65 61 6c 65 72 } //1 Zp_stealer
		$a_00_1 = {64 64 31 00 } //1 摤1
		$a_00_2 = {3f 75 69 64 3d 00 } //1 甿摩=
		$a_00_3 = {53 79 73 74 65 6d 5c 44 72 6b 5c } //1 System\Drk\
		$a_00_4 = {54 42 6f 74 54 68 72 65 61 64 } //1 TBotThread
		$a_00_5 = {2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 32 38 32 38 36 31 36 31 30 35 32 34 34 38 38 } //1 ---------------------------282861610524488
		$a_03_6 = {80 7d fb 01 75 ?? 81 fb b8 0b 00 00 76 ?? 6a 01 6a 00 6a 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_03_6  & 1)*1) >=7
 
}