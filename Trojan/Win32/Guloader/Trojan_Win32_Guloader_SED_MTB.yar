
rule Trojan_Win32_Guloader_SED_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 6b 00 69 00 62 00 73 00 74 00 69 00 6c 00 73 00 79 00 6e 00 73 00 6c 00 6f 00 76 00 73 00 36 00 32 00 2e 00 6b 00 6f 00 6e 00 } //01 00  Skibstilsynslovs62.kon
		$a_01_1 = {62 00 61 00 6c 00 64 00 72 00 69 00 61 00 6e 00 6f 00 6c 00 69 00 65 00 73 00 2e 00 76 00 69 00 74 00 } //01 00  baldrianolies.vit
		$a_01_2 = {70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 6d 00 65 00 72 00 69 00 6e 00 67 00 65 00 72 00 6e 00 65 00 2e 00 73 00 6b 00 61 00 } //01 00  programmeringerne.ska
		$a_01_3 = {73 00 70 00 69 00 6c 00 6c 00 65 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 2e 00 6b 00 6f 00 73 00 } //01 00  spillecomputer.kos
		$a_01_4 = {77 00 69 00 65 00 6e 00 65 00 72 00 62 00 72 00 64 00 73 00 73 00 74 00 61 00 6e 00 67 00 2e 00 62 00 6c 00 6f 00 } //01 00  wienerbrdsstang.blo
		$a_01_5 = {73 00 69 00 67 00 74 00 65 00 6c 00 69 00 6e 00 6a 00 65 00 6e 00 2e 00 6f 00 61 00 74 00 } //00 00  sigtelinjen.oat
	condition:
		any of ($a_*)
 
}