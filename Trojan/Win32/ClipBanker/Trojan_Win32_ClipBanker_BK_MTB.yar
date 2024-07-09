
rule Trojan_Win32_ClipBanker_BK_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 47 e6 83 f8 09 77 ?? 8b 4d d8 8d 45 c0 83 fe 10 0f 43 c1 80 38 31 74 ?? 83 fe 10 8d 45 c0 0f 43 c1 80 38 33 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}