
rule Ransom_Win32_Skystar_EA_MTB{
	meta:
		description = "Ransom:Win32/Skystar.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 } //01 00  YOUR FILES ARE ENCRYPTED
		$a_81_1 = {6e 6f 74 65 70 61 64 20 43 3a 5c 53 4b 59 53 54 41 52 53 52 41 4e 53 4f 4d 57 41 52 45 2e 74 78 74 } //01 00  notepad C:\SKYSTARSRANSOMWARE.txt
		$a_81_2 = {62 6c 61 63 6b 6d 6f 6f 6e } //01 00  blackmoon
		$a_81_3 = {53 6b 79 73 74 61 72 73 44 65 66 65 6e 64 65 72 } //01 00  SkystarsDefender
		$a_81_4 = {6d 79 61 70 70 2e 65 78 65 2e 53 4b 59 53 54 41 52 53 } //00 00  myapp.exe.SKYSTARS
	condition:
		any of ($a_*)
 
}