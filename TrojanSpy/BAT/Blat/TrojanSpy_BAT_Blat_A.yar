
rule TrojanSpy_BAT_Blat_A{
	meta:
		description = "TrojanSpy:BAT/Blat.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 00 6f 00 63 00 2e 00 6c 00 69 00 61 00 6d 00 67 00 40 00 6f 00 69 00 72 00 65 00 74 00 74 00 61 00 6c 00 62 00 } //01 00  moc.liamg@oirettalb
		$a_01_1 = {3d 00 3d 00 3d 00 20 00 43 00 79 00 62 00 65 00 72 00 2d 00 53 00 68 00 61 00 72 00 6b 00 20 00 3d 00 3d 00 3d 00 } //01 00  === Cyber-Shark ===
		$a_01_2 = {6b 62 48 6f 6f 6b } //01 00  kbHook
		$a_01_3 = {3d 00 3d 00 3d 00 3d 00 3d 00 20 00 53 00 74 00 65 00 61 00 6c 00 65 00 72 00 73 00 20 00 3d 00 3d 00 3d 00 3d 00 3d 00 } //00 00  ===== Stealers =====
	condition:
		any of ($a_*)
 
}