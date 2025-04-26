
rule Trojan_Win32_Dridex_BXF_MTB{
	meta:
		description = "Trojan:Win32/Dridex.BXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 75 c0 89 16 8b 55 c8 8b 0a 8b 55 b8 8b 12 0f b6 0c 0a 8b 16 8b 75 c4 8b 36 0f b6 14 16 31 d1 88 cb 8b 4d c8 8b 11 8b 75 b4 8b 0e 88 1c 11 e9 e4 fe ff ff } //10
		$a_01_1 = {5c 74 6f 77 6e 5c 77 68 65 72 65 5c 61 68 75 6e 67 2e 70 64 62 } //1 \town\where\ahung.pdb
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}