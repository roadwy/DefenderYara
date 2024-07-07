
rule Trojan_O97M_Krapame_A{
	meta:
		description = "Trojan:O97M/Krapame.A,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {6d 69 63 72 6f 73 6f 66 74 5f 70 61 79 6c 6f 61 64 5f 31 20 3d 20 74 6d 70 5f 64 69 72 20 2b 20 22 5c 22 20 26 20 72 61 6e 64 5f 6e 61 6d 65 20 26 20 22 2e 65 78 65 2e 31 22 } //1 microsoft_payload_1 = tmp_dir + "\" & rand_name & ".exe.1"
		$a_00_1 = {61 2e 57 72 69 74 65 4c 69 6e 65 20 28 22 40 73 74 61 72 74 20 2f 6d 69 6e 20 70 6f 77 65 22 20 26 20 43 68 72 28 31 31 34 29 20 26 20 22 73 68 22 20 26 20 43 68 72 28 31 30 31 29 20 26 20 22 6c 6c 2e 65 78 65 20 22 } //1 a.WriteLine ("@start /min powe" & Chr(114) & "sh" & Chr(101) & "ll.exe "
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}