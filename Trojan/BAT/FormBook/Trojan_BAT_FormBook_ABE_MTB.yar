
rule Trojan_BAT_FormBook_ABE_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 08 00 00 05 00 "
		
	strings :
		$a_01_0 = {57 bd 02 3e 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 48 00 00 00 2f 00 00 00 5e 00 00 00 12 01 00 00 34 01 00 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_3 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_5 = {70 62 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  pbDebuggerPresent
		$a_01_6 = {47 65 74 52 75 6e 74 69 6d 65 44 69 72 65 63 74 6f 72 79 } //01 00  GetRuntimeDirectory
		$a_01_7 = {43 6f 6e 66 75 73 65 72 } //00 00  Confuser
	condition:
		any of ($a_*)
 
}