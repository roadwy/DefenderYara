
rule PWS_Win32_Stimilina_E_bit{
	meta:
		description = "PWS:Win32/Stimilina.E!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {0f b6 4c 11 ff 81 f1 90 01 04 03 d9 8b cb c1 e1 90 01 01 8b f3 c1 ee 90 01 01 0b ce 2b d9 42 48 90 00 } //1
		$a_03_1 = {8b 12 8a 54 32 ff 8b 4d 90 01 01 8a 4c 19 ff 32 d1 88 54 30 ff 90 00 } //1
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 56 00 61 00 6c 00 76 00 65 00 5c 00 53 00 74 00 65 00 61 00 6d 00 } //1 Software\Valve\Steam
		$a_01_3 = {5c 00 43 00 6f 00 6e 00 66 00 69 00 67 00 5c 00 2a 00 2e 00 76 00 64 00 66 00 } //1 \Config\*.vdf
		$a_01_4 = {5c 00 77 00 61 00 6c 00 6c 00 65 00 74 00 2e 00 64 00 61 00 74 00 } //1 \wallet.dat
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}