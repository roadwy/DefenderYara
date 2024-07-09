
rule Trojan_Win32_Balisdat_gen_A{
	meta:
		description = "Trojan:Win32/Balisdat.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {6e 6f 69 73 72 65 56 74 6e 65 72 72 75 43 5c 73 77 6f 64 6e 69 57 5c 74 66 6f 73 6f 72 63 69 4d 5c 45 52 41 57 54 46 4f 53 5c [0-25] 6e 75 52 } //1
		$a_02_1 = {73 65 69 74 69 63 6f 65 67 [0-06] 2f 2f 3a 70 74 74 68 } //1
		$a_00_2 = {6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 land\Delphi\RTL
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}