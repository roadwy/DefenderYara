
rule TrojanDropper_Win32_Tibdef_B{
	meta:
		description = "TrojanDropper:Win32/Tibdef.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 3a 5c 50 72 6f 6a 65 6b 74 79 5c 45 76 75 6c 53 6f 66 74 5c 54 69 62 69 53 61 76 65 50 61 73 73 5c 50 72 6f 67 72 61 6d 79 5c 53 74 75 62 20 56 49 53 55 41 4c 5c 52 65 6c 65 61 73 65 5c 53 74 75 62 20 56 49 53 55 41 4c 2e 70 64 62 } //5 D:\Projekty\EvulSoft\TibiSavePass\Programy\Stub VISUAL\Release\Stub VISUAL.pdb
		$a_01_1 = {2d 2d 40 43 6f 75 6e 74 2d 2d 2d 2d 68 2d 2d } //3 --@Count----h--
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*3) >=8
 
}