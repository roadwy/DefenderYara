
rule Trojan_Win32_DriverLoader_ND_MTB{
	meta:
		description = "Trojan:Win32/DriverLoader.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 c0 8d 4f 08 83 39 00 74 48 40 83 c1 10 83 f8 10 7c f2 68 ?? ?? 00 00 e8 ae 0f 00 00 8b d8 59 85 db 74 4f } //3
		$a_03_1 = {4f c7 45 f0 ?? 00 00 00 8d 73 0c 6a 00 } //2
		$a_01_2 = {73 70 6f 6f 6c 73 76 2e 65 78 65 } //1 spoolsv.exe
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}