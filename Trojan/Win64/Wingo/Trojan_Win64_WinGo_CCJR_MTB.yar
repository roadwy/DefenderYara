
rule Trojan_Win64_WinGo_CCJR_MTB{
	meta:
		description = "Trojan:Win64/WinGo.CCJR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 0f b6 14 11 44 31 d7 41 88 3c 30 48 ff c6 4c 89 c0 4c 89 ca 48 39 f3 7e ?? 0f b6 3c 30 48 85 c9 74 ?? 49 89 c0 48 89 f0 49 89 d1 48 99 48 f7 f9 48 39 d1 77 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}