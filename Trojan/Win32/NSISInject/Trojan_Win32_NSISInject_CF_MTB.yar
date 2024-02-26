
rule Trojan_Win32_NSISInject_CF_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 6d 61 64 72 65 73 73 65 72 69 6e 67 2e 73 6c 61 } //01 00  Omadressering.sla
		$a_01_1 = {53 6c 75 6b 6e 65 6e 64 65 2e 74 78 74 } //01 00  Sluknende.txt
		$a_01_2 = {62 6c 75 66 66 6d 61 67 65 72 6e 65 2e 66 65 64 } //01 00  bluffmagerne.fed
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 74 6f 72 6d 65 6e 74 69 6c 6c 65 72 6e 65 } //01 00  Software\tormentillerne
		$a_01_4 = {75 6e 6d 75 74 65 64 2e 6d 61 6c } //01 00  unmuted.mal
		$a_01_5 = {6d 61 76 65 6b 61 74 61 72 2e 63 6f 6e } //00 00  mavekatar.con
	condition:
		any of ($a_*)
 
}