
rule Ransom_Win32_LockScreen_BA{
	meta:
		description = "Ransom:Win32/LockScreen.BA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b d8 68 a6 00 00 00 68 c4 00 00 00 } //1
		$a_03_1 = {38 ff 75 1a 6a 00 6a 00 68 90 09 06 00 a1 ?? ?? ?? ?? 83 } //1
		$a_01_2 = {c2 e2 e5 e4 e8 f2 e5 20 f1 fe e4 e0 20 ea ee e4 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}