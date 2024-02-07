
rule Trojan_Win32_Derusbi_J_bit{
	meta:
		description = "Trojan:Win32/Derusbi.J!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {40 65 63 68 6f 20 6f 66 66 0d 0a 70 69 6e 67 20 31 32 37 2e 31 20 3e 20 6e 75 6c 0d 0a 6e 65 74 20 73 74 6f 70 20 25 25 31 0d 0a 70 69 6e 67 20 31 32 37 2e 31 20 3e 20 6e 75 6c 0d 0a 6e 65 74 20 73 74 61 72 74 20 25 25 31 0d 0a 70 69 6e 67 20 31 32 37 2e 31 20 3e 20 6e 75 6c 0d 0a 64 65 6c 20 25 25 30 0d 0a } //01 00 
		$a_01_1 = {76 61 72 75 73 5f 73 65 72 76 69 63 65 5f 78 38 36 2e 64 6c 6c } //00 00  varus_service_x86.dll
	condition:
		any of ($a_*)
 
}