
rule Trojan_BAT_MatiexKeylogger_ZX_MTB{
	meta:
		description = "Trojan:BAT/MatiexKeylogger.ZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 69 72 65 46 6f 78 20 53 74 75 62 5c 46 69 72 65 46 6f 78 20 53 74 75 62 5c 6f 62 6a 5c 44 65 62 75 67 5c 56 4e 58 54 2e 70 64 62 } //1 FireFox Stub\FireFox Stub\obj\Debug\VNXT.pdb
		$a_01_1 = {3c 4d 6f 64 75 6c 65 3e } //1 <Module>
		$a_01_2 = {4d 2d 41 2d 54 2d 49 2d 45 2d 58 2d 2d 4b 2d 45 2d 59 2d 4c 2d 4f 2d 47 2d 45 2d 52 } //1 M-A-T-I-E-X--K-E-Y-L-O-G-E-R
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}