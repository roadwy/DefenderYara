
rule Ransom_Win32_Standartlocker_DA_MTB{
	meta:
		description = "Ransom:Win32/Standartlocker.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {4c 49 53 54 20 4f 46 20 59 4f 55 52 20 45 4e 43 52 59 50 54 45 44 20 46 49 4c 45 53 } //01 00  LIST OF YOUR ENCRYPTED FILES
		$a_81_1 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //01 00  @protonmail.com
		$a_81_2 = {53 74 61 6e 64 61 72 74 20 6c 6f 63 6b 65 72 } //01 00  Standart locker
		$a_81_3 = {62 69 74 63 6f 69 6e } //00 00  bitcoin
	condition:
		any of ($a_*)
 
}