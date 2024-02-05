
rule Trojan_Win32_Enchanim_A{
	meta:
		description = "Trojan:Win32/Enchanim.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 38 06 00 01 40 74 90 01 01 8b 40 0c 80 38 f8 74 90 01 01 80 38 e4 74 90 01 01 80 38 ec 0f 84 90 01 04 80 38 ed 0f 84 90 00 } //01 00 
		$a_03_1 = {81 38 06 00 01 40 74 90 01 01 8b 50 0c 80 3a f8 74 90 01 01 80 3a e4 74 90 01 01 80 3a ec 0f 84 90 01 04 80 3a ed 0f 84 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}