
rule Trojan_BAT_Nanobot_KZ{
	meta:
		description = "Trojan:BAT/Nanobot.KZ,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_03_0 = {5d 91 61 02 ?? 17 ?? 02 8e ?? 5d 91 ?? 20 00 01 00 00 ?? 20 00 01 00 00 5d ?? 9c } //2
		$a_00_1 = {41 6c 69 65 6e 41 6c 62 65 72 74 56 69 73 69 74 73 54 68 65 55 53 41 } //2 AlienAlbertVisitsTheUSA
		$a_00_2 = {41 74 74 61 63 6b 43 6f 6d 70 6c 65 74 65 64 } //1 AttackCompleted
		$a_00_3 = {41 74 74 61 63 6b 43 6f 6d 70 6c 65 74 65 64 45 76 65 6e 74 } //1 AttackCompletedEvent
		$a_00_4 = {41 49 41 74 74 61 63 6b } //1 AIAttack
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=7
 
}