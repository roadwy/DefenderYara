
rule Trojan_Win32_AdamantiumTheif_EH_MTB{
	meta:
		description = "Trojan:Win32/AdamantiumTheif.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {2b c8 8b c2 c1 e8 02 c1 e1 03 8b 04 86 d3 e8 88 04 1a 42 83 fa 14 72 e0 } //01 00 
		$a_01_1 = {46 00 72 00 65 00 65 00 56 00 42 00 75 00 63 00 6b 00 73 00 2e 00 68 00 74 00 6d 00 6c 00 } //00 00  FreeVBucks.html
	condition:
		any of ($a_*)
 
}