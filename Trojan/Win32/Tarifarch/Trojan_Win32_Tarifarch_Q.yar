
rule Trojan_Win32_Tarifarch_Q{
	meta:
		description = "Trojan:Win32/Tarifarch.Q,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 5f 66 2e 70 68 70 3f 73 75 62 5f 69 64 } //01 00  p_f.php?sub_id
		$a_01_1 = {6b 79 6e 67 6f 70 72 61 6e 6c 2e 63 6f 2e 63 63 } //01 00  kyngopranl.co.cc
		$a_01_2 = {69 66 68 70 66 78 6c 00 67 65 74 5f 70 65 65 72 73 } //01 00 
		$a_01_3 = {41 72 63 68 69 76 65 53 74 72 65 61 6d } //01 00  ArchiveStream
		$a_01_4 = {55 6e 6c 6f 63 6b 46 69 6c 65 } //00 00  UnlockFile
	condition:
		any of ($a_*)
 
}