
rule Trojan_Win32_Emotet_PDD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 07 0f b6 cb 03 c1 8b ce 99 f7 f9 8b 45 ?? 83 4d ?? ff 8a 8c 15 ?? ?? ?? ?? 30 08 } //1
		$a_81_1 = {38 78 38 4e 46 72 44 62 6c 67 56 64 7a 34 61 57 37 64 75 47 4e 5a 66 4f 43 77 38 56 30 39 51 47 4d } //1 8x8NFrDblgVdz4aW7duGNZfOCw8V09QGM
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}