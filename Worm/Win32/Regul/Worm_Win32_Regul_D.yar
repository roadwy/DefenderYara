
rule Worm_Win32_Regul_D{
	meta:
		description = "Worm:Win32/Regul.D,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 00 6f 70 65 6e 00 41 75 74 6f 52 75 6e 00 b4 f2 bf aa 28 26 4f 29 00 } //4
		$a_01_1 = {58 50 2d 00 65 78 70 6c 6f 72 65 72 20 00 2e 65 78 65 00 72 65 73 74 61 72 74 } //2 偘-硥汰牯牥 攮數爀獥慴瑲
		$a_01_2 = {57 4d 5f 48 54 4d 4c 5f 47 45 54 4f 42 4a 45 43 54 } //1 WM_HTML_GETOBJECT
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}