
rule Ransom_Linux_Filecoder_V_MTB{
	meta:
		description = "Ransom:Linux/Filecoder.V!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {52 33 64 34 31 26 74 5f 43 32 2e } //01 00  R3d41&t_C2.
		$a_00_1 = {63 75 72 6c 5f 65 61 73 79 5f 70 65 72 66 } //01 00  curl_easy_perf
		$a_00_2 = {74 2f 2d 64 65 78 2e 70 68 70 3f 63 30 6d 36 3d } //01 00  t/-dex.php?c0m6=
		$a_00_3 = {dd 2e 74 2f 2d 64 65 78 2e 70 68 70 3f 63 30 6d 36 3d ef 01 fb b7 47 } //00 00 
	condition:
		any of ($a_*)
 
}