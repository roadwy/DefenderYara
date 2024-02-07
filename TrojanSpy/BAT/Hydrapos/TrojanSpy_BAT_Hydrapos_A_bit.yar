
rule TrojanSpy_BAT_Hydrapos_A_bit{
	meta:
		description = "TrojanSpy:BAT/Hydrapos.A!bit,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 00 75 00 6d 00 70 00 2e 00 70 00 68 00 70 00 3f 00 77 00 3d 00 49 00 6e 00 66 00 65 00 63 00 74 00 61 00 64 00 6f 00 26 00 26 00 61 00 72 00 71 00 3d 00 } //01 00  dump.php?w=Infectado&&arq=
		$a_01_1 = {61 00 72 00 71 00 3d 00 61 00 74 00 75 00 61 00 6c 00 69 00 7a 00 61 00 2e 00 74 00 78 00 74 00 26 00 26 00 75 00 73 00 72 00 3d 00 } //01 00  arq=atualiza.txt&&usr=
		$a_01_2 = {75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 5c 00 70 00 72 00 6f 00 63 00 74 00 72 00 75 00 65 00 2e 00 74 00 78 00 74 00 } //00 00  uploads\proctrue.txt
	condition:
		any of ($a_*)
 
}