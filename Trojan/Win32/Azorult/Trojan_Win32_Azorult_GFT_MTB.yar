
rule Trojan_Win32_Azorult_GFT_MTB{
	meta:
		description = "Trojan:Win32/Azorult.GFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 ?? 03 c5 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 8d 44 24 ?? 89 4c 24 ?? e8 ?? ?? ?? ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 83 ef } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}