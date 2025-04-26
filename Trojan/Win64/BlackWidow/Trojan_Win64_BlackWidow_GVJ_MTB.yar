
rule Trojan_Win64_BlackWidow_GVJ_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.GVJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 8a 24 11 [0-32] 44 30 24 0f [0-32] 48 ff c1 [0-32] 48 89 c8 [0-32] 48 81 f9 ?? ?? ?? ?? 90 13 [0-32] 48 31 d2 [0-32] 49 f7 f3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}