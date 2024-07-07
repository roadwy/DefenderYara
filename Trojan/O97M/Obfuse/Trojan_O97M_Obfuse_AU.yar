
rule Trojan_O97M_Obfuse_AU{
	meta:
		description = "Trojan:O97M/Obfuse.AU,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 73 45 72 72 6f 72 20 43 56 45 72 72 28 } //1 IsError CVErr(
		$a_01_1 = {22 6d 64 2e 65 78 65 20 2f 22 20 2b 20 46 6f 72 6d 61 74 28 43 68 72 57 28 } //1 "md.exe /" + Format(ChrW(
		$a_01_2 = {5e 65 5e 6c 5e 4c 5e 2e 5e 45 5e 58 5e 65 5e } //1 ^e^l^L^.^E^X^e^
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}