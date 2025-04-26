
rule Trojan_Win32_Murureg_A{
	meta:
		description = "Trojan:Win32/Murureg.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c9 8a 9c 0d ?? ?? ?? ?? 8d 8c 0d ?? ?? ?? ?? 88 18 88 11 8a ca 02 08 0f b6 c1 8a 84 05 ?? ?? ?? ?? 32 04 37 88 06 46 ff 4d 08 75 b0 } //1
		$a_00_1 = {2e 70 68 70 3f 76 65 72 3d 25 56 45 52 25 26 63 76 65 72 3d 25 43 56 45 52 25 26 69 64 3d 25 49 44 25 } //1 .php?ver=%VER%&cver=%CVER%&id=%ID%
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}