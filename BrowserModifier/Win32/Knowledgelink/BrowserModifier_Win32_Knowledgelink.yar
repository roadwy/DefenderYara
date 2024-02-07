
rule BrowserModifier_Win32_Knowledgelink{
	meta:
		description = "BrowserModifier:Win32/Knowledgelink,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c 7b 38 41 46 33 33 43 35 31 2d 45 39 33 33 2d 34 30 42 33 2d 42 45 37 34 2d 45 39 45 36 33 30 43 36 30 36 30 43 7d } //01 00  Explorer\Browser Helper Objects\{8AF33C51-E933-40B3-BE74-E9E630C6060C}
		$a_01_1 = {70 6f 70 62 65 66 6f 72 65 74 69 6d 65 3d 00 00 70 6f 70 75 72 6c 3d 00 70 6f 70 6e 65 77 3d } //01 00 
		$a_01_2 = {26 6b 69 6e 64 3d 75 70 64 61 74 65 63 68 65 63 6b } //01 00  &kind=updatecheck
		$a_01_3 = {6b 6e 6f 77 6c 65 64 67 65 6c 69 6e 6b 73 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //00 00  湫睯敬杤汥湩獫䐮䱌䐀汬慃啮汮慯乤睯
	condition:
		any of ($a_*)
 
}