
rule Trojan_BAT_AgentTesla_RWA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 09 00 00 0a 00 "
		
	strings :
		$a_81_0 = {24 36 39 63 36 66 38 33 63 2d 61 63 65 36 2d 34 65 65 66 2d 38 65 36 62 2d 65 31 39 30 36 61 62 65 37 65 35 37 } //01 00  $69c6f83c-ace6-4eef-8e6b-e1906abe7e57
		$a_81_1 = {73 65 74 5f 55 73 65 53 79 73 74 65 6d 50 61 73 73 77 6f 72 64 43 68 61 72 } //01 00  set_UseSystemPasswordChar
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_3 = {67 65 74 5f 50 68 61 72 72 6d 61 50 6c 75 73 43 6f 6e 6e 65 63 74 69 6f 6e 53 74 72 69 6e 67 } //01 00  get_PharrmaPlusConnectionString
		$a_81_4 = {67 65 74 5f 52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //01 00  get_ResourceManager
		$a_81_5 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //01 00  RijndaelManaged
		$a_81_6 = {67 65 74 5f 4f 66 66 73 65 74 4d 61 72 73 68 61 6c 65 72 } //01 00  get_OffsetMarshaler
		$a_81_7 = {46 6f 72 6d 44 65 6c 65 67 61 74 65 73 } //01 00  FormDelegates
		$a_81_8 = {43 69 70 68 65 72 4d 6f 64 65 } //00 00  CipherMode
	condition:
		any of ($a_*)
 
}