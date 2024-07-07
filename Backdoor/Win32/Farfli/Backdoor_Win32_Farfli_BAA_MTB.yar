
rule Backdoor_Win32_Farfli_BAA_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 30 8b d1 81 e2 ff ff 00 00 8a 54 54 0c 32 da 41 88 1c 30 40 3b c7 72 } //2
		$a_01_1 = {63 3a 5c 57 69 6e 52 65 63 65 6c 5c 61 69 72 2e 64 6c 6c } //2 c:\WinRecel\air.dll
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}