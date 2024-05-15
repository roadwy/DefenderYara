
rule Trojan_Win32_Fragtor_NC_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 05 00 00 05 00 "
		
	strings :
		$a_81_0 = {74 69 73 66 75 5f 71 75 77 6f 66 5f 73 66 69 77 } //05 00  tisfu_quwof_sfiw
		$a_81_1 = {70 6c 61 79 5f 73 61 6e 77 73 75 } //05 00  play_sanwsu
		$a_81_2 = {6d 75 61 73 69 5f 61 66 6a 67 68 } //05 00  muasi_afjgh
		$a_81_3 = {67 63 72 79 5f 70 6b 5f 64 65 63 72 79 70 74 } //05 00  gcry_pk_decrypt
		$a_81_4 = {67 63 72 79 5f 70 6b 5f 65 6e 63 72 79 70 74 } //00 00  gcry_pk_encrypt
	condition:
		any of ($a_*)
 
}