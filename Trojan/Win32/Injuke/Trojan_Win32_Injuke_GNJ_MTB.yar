
rule Trojan_Win32_Injuke_GNJ_MTB{
	meta:
		description = "Trojan:Win32/Injuke.GNJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {2a 01 00 00 00 a4 a4 ?? ?? ?? ?? 2c 00 00 ae ?? ?? ?? ?? 28 5f 15 cc 2b 00 00 2a } //10
		$a_01_1 = {00 18 00 4e 23 00 00 01 00 30 30 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}