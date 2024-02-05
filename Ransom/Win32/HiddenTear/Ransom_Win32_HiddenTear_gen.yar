
rule Ransom_Win32_HiddenTear_gen{
	meta:
		description = "Ransom:Win32/HiddenTear.gen,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 02 00 "
		
	strings :
		$a_80_0 = {68 69 64 64 65 6e 5f 74 65 61 72 } //hidden_tear  02 00 
		$a_80_1 = {2f 68 69 64 64 65 6e 74 65 61 72 2f } ///hiddentear/  01 00 
		$a_80_2 = {74 61 72 67 65 74 55 52 4c } //targetURL  01 00 
		$a_80_3 = {65 6e 63 72 79 70 74 44 69 72 65 63 74 6f 72 79 } //encryptDirectory  01 00 
		$a_80_4 = {53 65 6e 64 50 61 73 73 77 6f 72 64 } //SendPassword  01 00 
		$a_80_5 = {73 74 61 72 74 41 63 74 69 6f 6e } //startAction  01 00 
		$a_80_6 = {62 79 74 65 73 54 6f 42 65 45 6e 63 72 79 70 74 65 64 } //bytesToBeEncrypted  00 00 
	condition:
		any of ($a_*)
 
}