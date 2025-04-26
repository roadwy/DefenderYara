
rule Trojan_WinNT_Alureon_X{
	meta:
		description = "Trojan:WinNT/Alureon.X,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {69 d2 b9 5e 68 5e 81 c2 00 09 24 31 } //1
		$a_01_1 = {8a 1c 01 88 18 8b ff 40 4a 75 f4 } //1
		$a_01_2 = {8b 45 fc 0f b7 00 8b d0 81 e2 00 f0 00 00 bb 00 30 00 00 66 3b d3 75 0d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}