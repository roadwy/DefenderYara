
rule Trojan_Win32_Tionas_B_dha{
	meta:
		description = "Trojan:Win32/Tionas.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 08 8b 11 c7 42 14 00 00 00 00 8b 45 08 8b 08 8b 55 14 89 51 18 8b 45 08 8b 08 8b 55 0c 89 51 1c 8b 45 08 8b 08 8b 55 10 89 51 20 8b 45 08 8b 08 c7 41 24 00 00 00 00 8b 55 08 8b 02 c7 40 28 00 00 00 00 68 00 04 00 00 8b 4d 08 } //1
		$a_00_1 = {37 38 77 4f 31 33 59 72 4a 30 63 42 2e 64 6c 6c } //4 78wO13YrJ0cB.dll
		$a_00_2 = {55 32 35 46 41 79 39 33 73 38 2e 64 6c 6c } //4 U25FAy93s8.dll
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*4+(#a_00_2  & 1)*4) >=5
 
}