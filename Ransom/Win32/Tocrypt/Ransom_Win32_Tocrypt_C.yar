
rule Ransom_Win32_Tocrypt_C{
	meta:
		description = "Ransom:Win32/Tocrypt.C,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 04 00 "
		
	strings :
		$a_03_0 = {84 c0 74 0f 90 09 2c 00 01 00 00 00 c7 44 90 01 02 00 00 00 00 c7 04 90 01 05 c7 85 90 01 04 0e 00 00 00 e8 90 01 04 b9 90 01 04 e8 90 01 04 84 c0 74 0f c7 85 90 01 04 01 00 00 00 e9 90 00 } //02 00 
		$a_00_1 = {5c 54 4f 58 20 52 41 4e 53 4f 4d 2e 68 74 6d 6c } //01 00  \TOX RANSOM.html
		$a_00_2 = {5c 74 6f 78 2e 6c 6f 67 } //01 00  \tox.log
		$a_00_3 = {5c 74 6f 78 5f 74 6f 72 5c } //01 00  \tox_tor\
		$a_00_4 = {2e 74 6f 78 63 72 79 70 74 } //01 00  .toxcrypt
		$a_00_5 = {5c 74 6f 78 2e 64 6f 6e 65 2e 6c 6f 67 } //00 00  \tox.done.log
		$a_00_6 = {5d 04 00 00 ef } //3e 03 
	condition:
		any of ($a_*)
 
}