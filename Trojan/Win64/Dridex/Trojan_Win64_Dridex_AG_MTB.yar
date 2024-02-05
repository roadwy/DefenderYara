
rule Trojan_Win64_Dridex_AG_MTB{
	meta:
		description = "Trojan:Win64/Dridex.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 03 00 "
		
	strings :
		$a_80_0 = {74 68 65 77 61 6c 6b 65 72 7a 34 62 6f 74 68 4e 6f 75 } //thewalkerz4bothNou  03 00 
		$a_80_1 = {43 61 74 65 67 6f 72 79 3a 47 6f 6f 67 6c 65 63 6f 6d 70 75 74 65 72 4a 50 } //Category:GooglecomputerJP  03 00 
		$a_80_2 = {30 72 45 78 70 6c 6f 72 65 72 33 6a 50 5a 32 39 2c 61 62 79 } //0rExplorer3jPZ29,aby  03 00 
		$a_80_3 = {52 68 46 69 72 65 66 6f 78 2c 33 4f 6e 4f 47 6f 6f 67 6c 65 4c 74 } //RhFirefox,3OnOGoogleLt  03 00 
		$a_80_4 = {62 6c 6f 67 67 65 72 73 43 68 72 6f 6d 65 78 4f 77 61 73 50 4e } //bloggersChromexOwasPN  03 00 
		$a_80_5 = {47 69 72 65 6e 64 65 72 69 6e 67 6d 65 64 34 61 76 61 69 6c 61 62 6c 65 78 78 72 65 6c 65 61 73 65 } //Girenderingmed4availablexxrelease  00 00 
	condition:
		any of ($a_*)
 
}