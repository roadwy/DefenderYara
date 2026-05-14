
rule Trojan_Win32_ClipBanker_ARA_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 44 3c 14 88 44 34 14 88 4c 3c 14 0f b6 44 34 14 03 c2 0f b6 c0 8a 44 04 14 30 83 00 10 40 00 43 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}