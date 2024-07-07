
rule Trojan_Win32_ClipBanker_BG_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 f8 09 77 90 01 01 83 90 01 01 10 8d 85 90 01 01 fd ff ff 0f 43 90 01 01 80 38 31 74 90 01 01 83 90 01 01 10 8d 85 90 01 01 fd ff ff 0f 43 90 01 01 80 38 33 75 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}