
rule Trojan_Win32_Sefnit_BZ{
	meta:
		description = "Trojan:Win32/Sefnit.BZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {46 83 fe 03 72 bd c6 45 ?? 01 eb 88 6a 04 } //3
		$a_03_1 = {6a 05 59 6a 0a 58 89 4d ?? 89 4d ?? 8d 8d ?? ?? ?? ?? c7 45 ?? 3c 00 00 00 } //3
		$a_01_2 = {6f 00 63 00 6c 00 2e 00 65 00 78 00 65 00 } //1 ocl.exe
		$a_01_3 = {63 00 64 00 61 00 2e 00 65 00 78 00 65 00 } //1 cda.exe
		$a_01_4 = {63 00 70 00 75 00 2e 00 65 00 78 00 65 00 } //1 cpu.exe
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}