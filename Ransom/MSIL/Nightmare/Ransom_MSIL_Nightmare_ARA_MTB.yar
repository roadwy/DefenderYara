
rule Ransom_MSIL_Nightmare_ARA_MTB{
	meta:
		description = "Ransom:MSIL/Nightmare.ARA!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 00 69 00 6c 00 65 00 6e 00 74 00 4e 00 69 00 67 00 68 00 74 00 6d 00 61 00 72 00 65 00 20 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 } //2 SilentNightmare Ransomware
		$a_01_1 = {43 00 6f 00 6d 00 70 00 6c 00 65 00 74 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 } //2 Complete encryption
		$a_01_2 = {48 00 79 00 70 00 65 00 72 00 2d 00 56 00 } //2 Hyper-V
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}