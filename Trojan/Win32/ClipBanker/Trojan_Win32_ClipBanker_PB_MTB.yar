
rule Trojan_Win32_ClipBanker_PB_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 28 ca 0f 10 41 ?? 66 0f ef c8 0f 11 49 ?? 0f 28 ca 0f 10 41 ?? 66 0f ef ?? 0f 11 ?? b0 [0-06] 0f 10 41 ?? 66 0f ef ?? 0f 11 [0-08] 0f 10 41 ?? 66 0f ef c8 0f 11 49 ?? 83 ?? 01 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}