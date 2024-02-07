
rule Trojan_Win64_IceID_SK_MTB{
	meta:
		description = "Trojan:Win64/IceID.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {79 75 67 61 65 6e 6a 61 6b 64 73 75 68 79 67 66 72 75 68 6a 77 65 6b 75 68 65 77 62 79 75 6a 61 73 73 } //05 00  yugaenjakdsuhygfruhjwekuhewbyujass
		$a_01_1 = {67 79 75 61 73 69 66 69 69 73 64 79 67 61 69 73 6a 64 6f 69 66 67 75 68 79 75 67 61 73 6a 73 6a 75 68 } //02 00  gyuasifiisdygaisjdoifguhyugasjsjuh
		$a_01_2 = {43 72 65 61 74 65 45 76 65 6e 74 57 } //02 00  CreateEventW
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00  VirtualAlloc
	condition:
		any of ($a_*)
 
}