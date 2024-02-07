
rule Trojan_Win32_Astaroth_A{
	meta:
		description = "Trojan:Win32/Astaroth.A,SIGNATURE_TYPE_CMDHSTR_EXT,0f 00 0f 00 03 00 00 05 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 } //05 00  cmd.exe
		$a_02_1 = {2e 00 6a 00 73 00 7c 00 63 00 61 00 6c 00 6c 00 20 00 25 00 90 01 06 3a 00 90 01 0a 3d 00 25 00 90 00 } //05 00 
		$a_00_2 = {2e 00 6a 00 73 00 7c 00 65 00 78 00 69 00 74 00 } //00 00  .js|exit
	condition:
		any of ($a_*)
 
}