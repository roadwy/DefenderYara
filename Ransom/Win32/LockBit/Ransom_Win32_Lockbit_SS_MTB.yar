
rule Ransom_Win32_Lockbit_SS_MTB{
	meta:
		description = "Ransom:Win32/Lockbit.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //01 00  InternetReadFile
		$a_03_1 = {68 74 74 70 3a 2f 2f 31 39 33 2e 32 33 33 2e 31 33 32 2e 31 37 37 2f 90 02 0f 2e 65 78 65 90 00 } //01 00 
		$a_81_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 57 } //01 00  ShellExecuteW
		$a_81_3 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 57 } //00 00  InternetOpenUrlW
	condition:
		any of ($a_*)
 
}