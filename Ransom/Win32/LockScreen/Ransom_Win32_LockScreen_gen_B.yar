
rule Ransom_Win32_LockScreen_gen_B{
	meta:
		description = "Ransom:Win32/LockScreen.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {b0 65 88 45 e0 8d 4d dc b0 6c 51 c7 45 dc 6b 65 72 6e } //01 00 
		$a_00_1 = {0f b7 4c 02 02 83 c0 02 66 89 08 66 3b cb 75 f0 } //00 00 
	condition:
		any of ($a_*)
 
}