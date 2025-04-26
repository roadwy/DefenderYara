
rule Trojan_Win32_Redline_TZX_MTB{
	meta:
		description = "Trojan:Win32/Redline.TZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 54 2e ?? 83 f0 ?? 81 c2 ?? ?? ?? ?? 03 c7 c1 e2 ?? 8a 04 02 88 44 2e ?? 8b c1 83 f8 ?? 7c ?? eb ?? 8d 9b ?? ?? ?? ?? 0f b6 14 30 0f b6 4c 30 ?? 81 c2 ?? ?? ?? ?? c1 e2 ?? 03 cf 8a 0c 0a 88 0c 30 48 83 f8 ?? 7d } //1
		$a_01_1 = {7a 61 73 66 61 66 73 61 2e 65 78 65 } //1 zasfafsa.exe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}