
rule Trojan_Win64_BlackWidow_GVI_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.GVI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 30 1c 0f [0-10] 48 ff c1 [0-10] 48 89 c8 [0-10] 48 81 f9 ?? ?? ?? ?? 90 13 [0-20] 48 31 d2 [0-10] 49 f7 f4 [0-10] 45 8a 1c 12 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}