
rule Ransom_Win32_Radamcrypt_A{
	meta:
		description = "Ransom:Win32/Radamcrypt.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 25 73 2e 52 44 4d } //01 00  %s%s.RDM
		$a_01_1 = {59 4f 55 52 5f 46 49 4c 45 53 2e 75 72 6c } //01 00  YOUR_FILES.url
		$a_01_2 = {69 64 3d 25 73 26 61 70 74 3d 25 69 26 6f 73 3d 25 73 26 69 70 3d 25 73 26 62 69 74 73 3d 25 73 } //01 00  id=%s&apt=%i&os=%s&ip=%s&bits=%s
		$a_01_3 = {52 61 64 61 6d 61 6e 74 5f 76 31 5f 4b 6c 69 74 73 63 68 6b 6f 5f 6e 75 6d 62 65 72 5f 6f 6e 65 } //01 00  Radamant_v1_Klitschko_number_one
		$a_01_4 = {70 72 6f 63 65 73 73 20 63 61 6c 6c 20 63 72 65 61 74 65 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 22 } //01 00  process call create "cmd.exe /c vssadmin delete shadows /all /quiet"
		$a_01_5 = {55 52 4c 3d 68 74 74 70 3a 2f 2f 25 73 2f 6c 64 2f 3f 69 64 3d 25 73 } //00 00  URL=http://%s/ld/?id=%s
		$a_01_6 = {00 80 10 } //00 00 
	condition:
		any of ($a_*)
 
}