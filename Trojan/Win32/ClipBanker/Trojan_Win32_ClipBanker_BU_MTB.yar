
rule Trojan_Win32_ClipBanker_BU_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.BU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 02 8d 4c 24 20 83 fe ?? 0f 43 4c 24 20 42 88 04 0f 8b 7c 24 30 47 89 7c 24 30 3b 54 24 1c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}