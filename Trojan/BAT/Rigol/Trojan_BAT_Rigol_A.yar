
rule Trojan_BAT_Rigol_A{
	meta:
		description = "Trojan:BAT/Rigol.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {38 34 65 33 31 38 35 36 2d 36 38 33 62 2d 34 31 63 30 2d 38 31 64 64 2d 61 30 32 64 38 62 37 39 35 30 32 36 } //1 84e31856-683b-41c0-81dd-a02d8b795026
		$a_01_1 = {5c 65 78 65 72 75 6e 65 72 5c 65 78 65 72 75 6e 65 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 65 78 65 72 75 6e 65 72 2e 70 64 62 } //1 \exeruner\exeruner\obj\Debug\exeruner.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}