
rule Trojan_MacOS_Amos_AN_MTB{
	meta:
		description = "Trojan:MacOS/Amos.AN!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e8 04 80 52 08 00 08 4a e8 83 02 39 2a fc 78 d3 48 09 1c 52 e8 7f 02 39 2b fc 70 d3 e9 0d 80 52 68 01 09 4a e8 7b 02 39 2c fc 68 d3 93 0e 80 52 88 01 13 4a e8 77 02 39 2d fc 60 d3 68 0e 80 52 ae 01 08 4a 68 0e 80 52 ee 73 02 39 2e fc 58 d3 cf 01 1b 52 ef 6f 02 39 } //1
		$a_03_1 = {1f 21 00 f1 00 ?? ?? ?? 2a 01 08 8b 4b 01 40 39 4c 41 40 39 8b 01 0b 4a 4b 41 00 39 08 05 00 91 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}