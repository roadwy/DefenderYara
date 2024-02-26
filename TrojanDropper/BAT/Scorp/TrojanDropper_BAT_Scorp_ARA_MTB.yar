
rule TrojanDropper_BAT_Scorp_ARA_MTB{
	meta:
		description = "TrojanDropper:BAT/Scorp.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_80_0 = {43 3a 5c 43 6f 64 65 5c 47 54 41 56 5c 54 65 74 73 74 41 75 74 6f 72 75 6e 5c 54 65 74 73 74 41 75 74 6f 72 75 6e 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 54 65 74 73 74 41 75 74 6f 72 75 6e 2e 70 64 62 } //C:\Code\GTAV\TetstAutorun\TetstAutorun\obj\Release\TetstAutorun.pdb  02 00 
		$a_80_1 = {54 65 73 74 2e 6c 6e 6b } //Test.lnk  00 00 
	condition:
		any of ($a_*)
 
}