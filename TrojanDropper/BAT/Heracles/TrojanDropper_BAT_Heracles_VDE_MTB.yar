
rule TrojanDropper_BAT_Heracles_VDE_MTB{
	meta:
		description = "TrojanDropper:BAT/Heracles.VDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 55 43 4b 5f 49 53 5f 41 4c 57 41 59 53 5f 52 45 41 4c } //5 FUCK_IS_ALWAYS_REAL
		$a_01_1 = {44 52 49 45 52 53 53 53 53 5f 4c 4f 41 44 5f 41 55 54 4f 5f 49 4e 5f 50 52 4f 43 45 53 53 53 } //5 DRIERSSSS_LOAD_AUTO_IN_PROCESSS
		$a_00_2 = {41 00 6e 00 64 00 72 00 6f 00 69 00 64 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 2e 00 65 00 78 00 65 00 } //5 AndroidProcess.exe
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_00_2  & 1)*5) >=15
 
}