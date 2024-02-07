
rule Trojan_Win32_Ickerpo_A{
	meta:
		description = "Trojan:Win32/Ickerpo.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 07 00 05 00 00 05 00 "
		
	strings :
		$a_03_0 = {f3 a6 0f 94 c0 83 c0 03 8b f8 8b 44 bb fc 80 38 23 74 24 8b 03 6a 21 50 e8 90 01 04 c6 00 00 8b 03 40 6a 7f 50 8d 85 7c ff ff ff 90 00 } //05 00 
		$a_01_1 = {8a 08 3a 0a 75 18 84 c9 74 10 8a 48 01 3a 4a 01 75 0c 03 c3 03 d3 84 c9 75 e6 33 c0 eb 05 1b c0 83 d8 ff 85 c0 74 0d } //01 00 
		$a_01_2 = {70 69 6e 67 20 31 2e 31 2e 31 2e 31 20 2d 77 20 35 30 30 30 20 3e 6e 75 6c 00 } //01 00  楰杮ㄠㄮㄮㄮⴠ⁷〵〰㸠畮l
		$a_01_3 = {23 78 63 6f 64 00 } //01 00  砣潣d
		$a_01_4 = {52 61 7a 6f 72 4d 69 6e 74 } //00 00  RazorMint
	condition:
		any of ($a_*)
 
}