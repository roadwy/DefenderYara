
rule Trojan_Win32_Powemet_K_attk{
	meta:
		description = "Trojan:Win32/Powemet.K!attk,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 0b 00 04 00 00 ffffff9c ffffffff "
		
	strings :
		$a_00_0 = {2e 00 64 00 6c 00 6c 00 } //0a 00  .dll
		$a_00_1 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 } //01 00  regsvr32
		$a_00_2 = {2e 00 6a 00 70 00 67 00 } //01 00  .jpg
		$a_00_3 = {2e 00 63 00 73 00 76 00 } //00 00  .csv
	condition:
		any of ($a_*)
 
}