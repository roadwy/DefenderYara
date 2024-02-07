
rule Trojan_Win95_Koadic_F_attk{
	meta:
		description = "Trojan:Win95/Koadic.F!attk,SIGNATURE_TYPE_PEHSTR_EXT,ffffffb0 04 ffffffb0 04 04 00 00 64 00 "
		
	strings :
		$a_02_0 = {5c 77 69 6e 33 32 5c 6d 69 6d 69 73 68 69 6d 5c 52 65 66 6c 65 63 74 69 76 65 44 4c 4c 49 6e 6a 65 63 74 69 6f 6e 5c 90 02 08 52 65 6c 65 61 73 65 5c 6d 69 6d 69 73 68 69 6d 2e 70 64 62 90 00 } //64 00 
		$a_00_1 = {6d 69 6d 69 73 68 69 6d 2e 64 6c 6c } //64 00  mimishim.dll
		$a_00_2 = {6d 69 6d 69 73 68 69 6d 2e 78 36 34 2e 64 6c 6c } //e8 03  mimishim.x64.dll
		$a_00_3 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 40 } //00 00  ReflectiveLoader@
	condition:
		any of ($a_*)
 
}