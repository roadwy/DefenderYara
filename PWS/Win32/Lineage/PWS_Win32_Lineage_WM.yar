
rule PWS_Win32_Lineage_WM{
	meta:
		description = "PWS:Win32/Lineage.WM,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {ba 14 45 40 00 b8 6c 66 40 00 e8 93 e5 ff ff b8 6c 66 40 00 e8 25 e3 ff ff e8 0c e1 ff ff 68 28 45 40 00 8d 55 e8 33 c0 e8 59 e2 ff ff } //1
		$a_01_1 = {64 65 6c 20 25 30 } //1 del %0
		$a_01_2 = {63 3a 5c 61 61 2e 62 61 74 } //1 c:\aa.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}