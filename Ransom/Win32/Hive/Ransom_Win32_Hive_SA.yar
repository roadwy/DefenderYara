
rule Ransom_Win32_Hive_SA{
	meta:
		description = "Ransom:Win32/Hive.SA,SIGNATURE_TYPE_CMDHSTR_EXT,65 00 65 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 } //64 00 
		$a_00_1 = {5c 00 6e 00 65 00 74 00 6c 00 6f 00 67 00 6f 00 6e 00 5c 00 78 00 78 00 78 00 2e 00 65 00 78 00 65 00 20 00 2d 00 75 00 } //64 00 
		$a_00_2 = {5c 00 6e 00 65 00 74 00 6c 00 6f 00 67 00 6f 00 6e 00 5c 00 78 00 78 00 78 00 78 00 2e 00 65 00 78 00 65 00 20 00 2d 00 75 00 } //00 00 
	condition:
		any of ($a_*)
 
}