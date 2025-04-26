
rule Trojan_BAT_PeLoad_SK_MTB{
	meta:
		description = "Trojan:BAT/PeLoad.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 75 6e 50 45 5c 6f 62 6a 5c 44 65 62 75 67 5c 52 75 6e 50 45 2e 70 64 62 } //1 RunPE\obj\Debug\RunPE.pdb
		$a_01_1 = {24 61 38 37 32 63 65 31 64 2d 31 36 36 61 2d 34 63 38 61 2d 39 65 66 32 2d 30 62 37 64 32 38 63 38 62 32 65 39 } //1 $a872ce1d-166a-4c8a-9ef2-0b7d28c8b2e9
		$a_01_2 = {52 75 6e 50 45 2e 65 78 65 } //1 RunPE.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}