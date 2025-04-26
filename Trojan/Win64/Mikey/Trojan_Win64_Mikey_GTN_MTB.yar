
rule Trojan_Win64_Mikey_GTN_MTB{
	meta:
		description = "Trojan:Win64/Mikey.GTN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 e8 1a ee 29 3e c0 29 38 } //5
		$a_03_1 = {88 29 30 11 0c e8 f3 0b a8 ?? ?? ?? ?? 2a 51 01 08 7e fe 02 0f } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}