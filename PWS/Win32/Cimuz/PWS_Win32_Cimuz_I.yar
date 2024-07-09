
rule PWS_Win32_Cimuz_I{
	meta:
		description = "PWS:Win32/Cimuz.I,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {76 10 8b c1 6a 05 99 ?? f7 ?? 30 14 ?? 41 3b ?? 72 f0 8b 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? bd ?? ?? ?? ?? ?? 55 ff d6 ?? e8 ?? ?? ff ff } //5
		$a_01_1 = {3d c5 f8 ae ca } //1
		$a_01_2 = {52 54 5f 52 45 47 44 4c 4c 00 } //1 呒剟䝅䱄L
		$a_01_3 = {52 54 5f 44 4c 4c 00 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}