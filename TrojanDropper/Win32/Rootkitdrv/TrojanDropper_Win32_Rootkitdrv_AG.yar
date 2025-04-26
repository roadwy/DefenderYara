
rule TrojanDropper_Win32_Rootkitdrv_AG{
	meta:
		description = "TrojanDropper:Win32/Rootkitdrv.AG,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 03 47 14 8b ce 03 4f 0c 81 3f 2e 64 61 74 } //1
		$a_01_1 = {8d b3 f8 00 00 00 8b 45 08 03 46 14 8b cf 03 4e 0c 81 3e 2e 64 61 74 } //1
		$a_01_2 = {8b 5d 08 8b 45 0c 8a 0f 80 f9 00 74 09 30 0b 48 } //4
		$a_03_3 = {64 a1 18 00 00 00 8b 40 30 8b 1d ?? ?? ?? ?? 89 58 08 } //2
		$a_01_4 = {83 c6 03 56 ff 15 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*4+(#a_03_3  & 1)*2+(#a_01_4  & 1)*2) >=7
 
}