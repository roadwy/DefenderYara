
rule Trojan_O97M_Miner_F{
	meta:
		description = "Trojan:O97M/Miner.F,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f 73 78 50 59 7a 37 66 54 } //1 http://pastebin.com/raw/sxPYz7fT
	condition:
		((#a_00_0  & 1)*1) >=1
 
}