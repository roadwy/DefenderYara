
rule Ransom_Win32_GermanWiper_SA_dha{
	meta:
		description = "Ransom:Win32/GermanWiper.SA!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 50 5f 44 45 53 54 5f 50 4f 52 54 5f 55 4e 52 45 41 43 48 41 42 4c 45 20 28 31 31 30 30 35 29 } //1 IP_DEST_PORT_UNREACHABLE (11005)
		$a_01_1 = {6e 69 6e 65 2e 65 78 65 } //1 nine.exe
		$a_01_2 = {46 00 72 00 69 00 63 00 74 00 69 00 6f 00 6e 00 20 00 54 00 77 00 65 00 65 00 74 00 65 00 72 00 20 00 43 00 61 00 73 00 74 00 69 00 6e 00 67 00 } //1 Friction Tweeter Casting
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}