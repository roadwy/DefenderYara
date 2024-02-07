
rule VirTool_BAT_Obfuscator_BQ{
	meta:
		description = "VirTool:BAT/Obfuscator.BQ,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {39 72 2c ef d7 f0 bd 14 bc 61 a8 e0 d8 53 27 fe 9f d3 7c 5b 16 e2 6b b9 f7 8d 0e 05 f7 30 64 dd d7 00 57 7d 5e 44 91 be 9e 16 ae ef ae 17 b7 4a ac b1 bb b3 18 0c af 1f fb 52 c1 be 13 61 74 bf c1 ea d7 2a cf 4e 9b 45 } //01 00 
		$a_00_1 = {57 00 69 00 6e 00 48 00 54 00 54 00 50 00 } //01 00  WinHTTP
		$a_00_2 = {41 00 75 00 74 00 6f 00 2d 00 44 00 69 00 73 00 63 00 6f 00 76 00 65 00 72 00 79 00 } //01 00  Auto-Discovery
		$a_00_3 = {57 00 65 00 62 00 20 00 50 00 72 00 6f 00 78 00 79 00 } //00 00  Web Proxy
		$a_00_4 = {96 46 00 00 00 } //00 42 
	condition:
		any of ($a_*)
 
}