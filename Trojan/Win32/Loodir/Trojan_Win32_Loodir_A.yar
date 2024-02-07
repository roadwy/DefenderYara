
rule Trojan_Win32_Loodir_A{
	meta:
		description = "Trojan:Win32/Loodir.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 5c 2e 5c 44 69 73 6b 44 61 74 61 4d 67 72 } //01 00  \\.\DiskDataMgr
		$a_01_1 = {81 bc 11 20 03 00 00 aa 99 88 77 75 17 } //00 00 
	condition:
		any of ($a_*)
 
}