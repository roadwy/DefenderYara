
rule Trojan_Win32_Makoob_NM_MTB{
	meta:
		description = "Trojan:Win32/Makoob.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {70 00 6c 00 61 00 6e 00 6b 00 65 00 6e 00 64 00 65 00 20 00 6f 00 72 00 63 00 68 00 69 00 64 00 } //02 00  plankende orchid
		$a_01_1 = {62 00 61 00 6e 00 64 00 69 00 74 00 74 00 69 00 20 00 73 00 63 00 6f 00 72 00 70 00 69 00 69 00 64 00 2e 00 65 00 78 00 65 00 } //02 00  banditti scorpiid.exe
		$a_01_2 = {66 00 69 00 6c 00 65 00 72 00 65 00 64 00 65 00 20 00 70 00 61 00 72 00 74 00 73 00 68 00 72 00 69 00 6e 00 67 00 73 00 72 00 65 00 67 00 65 00 6c 00 65 00 6e 00 20 00 6b 00 6e 00 61 00 6c 00 6c 00 65 00 72 00 69 00 73 00 74 00 } //00 00  filerede partshringsregelen knallerist
	condition:
		any of ($a_*)
 
}