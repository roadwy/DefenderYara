
rule Trojan_Win32_Hancitor_FGQ_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.FGQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 39 8a c8 80 e9 3b 00 0d 90 01 04 81 7c 24 90 01 05 90 18 83 c5 33 33 c9 2b e8 1b ce 01 2d 90 01 04 0f b6 6c 24 12 11 0d 90 01 04 4d 0f af 2d 90 01 04 8b 4c 24 14 83 44 24 90 02 02 81 c7 20 77 00 01 89 39 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}