
rule Trojan_Win32_Zloader_DHB_MTB{
	meta:
		description = "Trojan:Win32/Zloader.DHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 07 89 4d f0 89 c3 f6 d3 80 e3 ?? 6a 00 6a 00 6a ?? 50 e8 ?? ?? ?? ?? 8b 4d f0 83 c4 10 08 d8 30 c8 c1 c1 ?? 34 ?? 88 07 47 4e 75 } //1
		$a_81_1 = {64 6a 6c 75 66 6c 63 7a 72 67 65 66 70 68 74 69 77 65 67 63 } //1 djluflczrgefphtiwegc
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}