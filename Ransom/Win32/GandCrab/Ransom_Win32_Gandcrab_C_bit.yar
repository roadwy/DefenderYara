
rule Ransom_Win32_Gandcrab_C_bit{
	meta:
		description = "Ransom:Win32/Gandcrab.C!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 00 52 00 41 00 42 00 2d 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 2e 00 74 00 78 00 74 00 } //1 CRAB-DECRYPT.txt
		$a_01_1 = {72 00 61 00 6e 00 73 00 6f 00 6d 00 5f 00 69 00 64 00 3d 00 } //1 ransom_id=
		$a_01_2 = {65 6e 63 72 79 70 74 69 6f 6e 2e 64 6c 6c 00 5f 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } //1 湥牣灹楴湯搮汬开敒汦捥楴敶潌摡牥
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}