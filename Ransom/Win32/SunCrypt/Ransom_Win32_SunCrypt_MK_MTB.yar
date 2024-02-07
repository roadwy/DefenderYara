
rule Ransom_Win32_SunCrypt_MK_MTB{
	meta:
		description = "Ransom:Win32/SunCrypt.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 0c 00 00 02 00 "
		
	strings :
		$a_81_0 = {2d 6e 6f 73 68 61 72 65 73 } //02 00  -noshares
		$a_81_1 = {2d 6e 6f 6d 75 74 65 78 } //02 00  -nomutex
		$a_81_2 = {2d 6e 6f 72 65 70 6f 72 74 } //02 00  -noreport
		$a_81_3 = {2d 6e 6f 73 65 72 76 69 63 65 73 } //02 00  -noservices
		$a_81_4 = {2d 61 6c 6c } //02 00  -all
		$a_81_5 = {2d 61 67 72 } //02 00  -agr
		$a_81_6 = {2d 70 61 74 68 } //02 00  -path
		$a_81_7 = {2d 6c 6f 67 } //0a 00  -log
		$a_81_8 = {24 52 65 63 79 63 6c 65 2e 62 69 6e } //0a 00  $Recycle.bin
		$a_81_9 = {59 4f 55 52 5f 46 49 4c 45 53 5f 41 52 45 5f 45 4e 43 52 59 50 54 45 44 2e 48 54 4d 4c } //0a 00  YOUR_FILES_ARE_ENCRYPTED.HTML
		$a_81_10 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b } //0a 00  expand 32-byte k
		$a_81_11 = {65 78 70 61 6e 64 20 31 36 2d 62 79 74 65 20 6b } //00 00  expand 16-byte k
		$a_00_12 = {5d 04 00 00 5e 89 04 80 5c 3b 00 00 5f 89 04 80 00 00 01 00 04 00 25 00 54 72 6f 6a 61 6e 44 6f 77 6e 6c 6f 61 64 65 72 } //3a 4f 
	condition:
		any of ($a_*)
 
}