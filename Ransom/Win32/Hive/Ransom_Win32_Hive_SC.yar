
rule Ransom_Win32_Hive_SC{
	meta:
		description = "Ransom:Win32/Hive.SC,SIGNATURE_TYPE_CMDHSTR_EXT,65 00 65 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 } //64 00 
		$a_02_1 = {5c 00 6e 00 65 00 74 00 6c 00 6f 00 67 00 6f 00 6e 00 5c 00 79 00 79 00 79 00 2e 00 64 00 6c 00 6c 00 90 02 10 2d 00 75 00 90 02 30 3a 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}