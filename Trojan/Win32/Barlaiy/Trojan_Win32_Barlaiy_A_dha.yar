
rule Trojan_Win32_Barlaiy_A_dha{
	meta:
		description = "Trojan:Win32/Barlaiy.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 10 00 00 bf 58 07 01 00 } //01 00 
		$a_01_1 = {6a 02 68 fc fe ff ff 53 e8 e3 14 00 00 bf 04 01 00 00 } //01 00 
		$a_01_2 = {52 75 6e 64 6c 6c 33 32 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}