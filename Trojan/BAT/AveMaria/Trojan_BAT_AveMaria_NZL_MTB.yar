
rule Trojan_BAT_AveMaria_NZL_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NZL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {73 64 64 64 64 66 66 73 68 64 6a 66 66 66 66 66 67 6a 73 6b 64 67 73 61 63 73 61 66 70 } //01 00  sddddffshdjfffffgjskdgsacsafp
		$a_81_1 = {66 66 63 68 6b 66 66 61 66 66 73 64 73 73 66 6a } //01 00  ffchkffaffsdssfj
		$a_81_2 = {6a 73 66 68 64 67 66 66 66 66 64 66 66 64 6b 66 67 66 67 6a } //01 00  jsfhdgffffdffdkfgfgj
		$a_81_3 = {68 73 66 6a 66 67 66 68 73 64 64 66 64 66 66 68 66 } //01 00  hsfjfgfhsddfdffhf
		$a_81_4 = {6a 64 64 73 73 73 73 73 73 73 73 73 73 73 73 73 73 64 66 73 73 73 73 73 73 73 66 66 73 64 64 68 66 68 6b 66 6a } //01 00  jddssssssssssssssdfsssssssffsddhfhkfj
		$a_81_5 = {52 66 63 32 38 39 38 44 65 72 69 76 65 42 79 74 65 73 } //01 00  Rfc2898DeriveBytes
		$a_81_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}