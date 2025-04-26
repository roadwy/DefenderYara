
rule Trojan_Win32_Kovter_LK_MTB{
	meta:
		description = "Trojan:Win32/Kovter.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 db 8a 19 c1 eb 04 8a 9b ?? ?? ?? ?? 88 1e 46 8a 19 80 e3 0f 81 e3 ff 00 00 00 8a 9b ?? ?? ?? ?? 88 1e 46 41 4f 75 d8 } //1
		$a_01_1 = {32 32 32 2e 64 6c 6c } //1 222.dll
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}