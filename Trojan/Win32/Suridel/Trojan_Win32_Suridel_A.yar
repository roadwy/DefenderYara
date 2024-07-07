
rule Trojan_Win32_Suridel_A{
	meta:
		description = "Trojan:Win32/Suridel.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 6f 70 79 5f 76 69 72 75 73 5f 63 61 63 68 65 } //1 Copy_virus_cache
		$a_01_1 = {7a 61 6d 65 6e 61 5f 66 61 69 6c } //1 zamena_fail
		$a_01_2 = {6b 69 63 6b 5f 61 6e 74 69 76 69 72 75 73 } //1 kick_antivirus
		$a_01_3 = {23 00 56 00 49 00 52 00 55 00 53 00 20 00 32 00 30 00 30 00 35 00 5c 00 76 00 69 00 72 00 75 00 73 00 20 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 } //1 #VIRUS 2005\virus rundll32
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}