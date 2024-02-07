
rule Trojan_Win32_Axhuan{
	meta:
		description = "Trojan:Win32/Axhuan,SIGNATURE_TYPE_PEHSTR,0a 00 08 00 0a 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 78 75 68 75 61 6e 2e 69 6e 69 } //02 00  \xuhuan.ini
		$a_01_1 = {5c 78 75 68 75 61 6e 2e 74 6d 70 } //02 00  \xuhuan.tmp
		$a_01_2 = {5c 78 75 68 75 61 6e 2e 65 78 65 } //02 00  \xuhuan.exe
		$a_01_3 = {5b 78 75 68 75 61 6e 5d } //02 00  [xuhuan]
		$a_01_4 = {5c 53 41 4d 2e 64 61 74 } //01 00  \SAM.dat
		$a_01_5 = {63 6d 64 2e 65 78 65 20 2f 43 20 69 70 63 6f 6e 66 69 67 20 2d 61 6c 6c 3e 63 3a 5c 73 79 73 2e 74 6d 70 } //01 00  cmd.exe /C ipconfig -all>c:\sys.tmp
		$a_01_6 = {63 3a 5c 73 79 73 2e 74 6d 70 } //01 00  c:\sys.tmp
		$a_01_7 = {5c 72 6d 64 72 76 2e 64 6c 6c } //01 00  \rmdrv.dll
		$a_01_8 = {5c 72 6d 64 6c 6c 2e 64 6c 6c } //01 00  \rmdll.dll
		$a_01_9 = {4d 69 63 72 6f 43 53 43 } //00 00  MicroCSC
	condition:
		any of ($a_*)
 
}