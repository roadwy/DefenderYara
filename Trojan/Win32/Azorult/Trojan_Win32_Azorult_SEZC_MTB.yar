
rule Trojan_Win32_Azorult_SEZC_MTB{
	meta:
		description = "Trojan:Win32/Azorult.SEZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {78 6f 76 61 68 75 67 65 73 2e 65 78 65 } //2 xovahuges.exe
		$a_01_1 = {4d 79 46 75 6e 63 31 32 34 40 40 34 } //1 MyFunc124@@4
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}