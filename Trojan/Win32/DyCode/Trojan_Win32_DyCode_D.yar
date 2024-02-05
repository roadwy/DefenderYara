
rule Trojan_Win32_DyCode_D{
	meta:
		description = "Trojan:Win32/DyCode.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff d0 8b c8 81 e9 ae f6 ff ff 51 } //01 00 
		$a_03_1 = {55 8b ec 83 c4 e8 03 90 01 01 f7 90 01 02 c9 c2 28 00 90 00 } //01 00 
		$a_03_2 = {c1 c0 07 03 90 01 01 41 80 39 00 e9 90 01 03 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}