
rule Ransom_Win32_OutCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/OutCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 03 00 "
		
	strings :
		$a_02_0 = {83 7d d8 10 7d 90 01 01 8b 90 01 02 8b 90 01 02 8b 90 01 02 8a 0c 1a 8b 90 01 02 c1 e6 04 03 90 01 02 8b 90 01 02 8b 90 01 02 30 90 01 02 ff 45 90 01 01 eb 90 00 } //01 00 
		$a_00_1 = {61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //01 00  as been encrypted
		$a_00_2 = {48 45 53 4f 59 41 4d 41 45 5a 41 4b 4d 49 52 49 50 41 5a 48 41 48 45 53 4f 59 41 4d 41 45 5a 41 4b 4d 49 52 49 50 41 5a 48 41 } //01 00  HESOYAMAEZAKMIRIPAZHAHESOYAMAEZAKMIRIPAZHA
		$a_00_3 = {5f 6f 75 74 } //01 00  _out
		$a_00_4 = {3d 3d 3d 20 42 79 70 61 73 73 65 64 20 3d 3d 3d } //00 00  === Bypassed ===
		$a_00_5 = {5d 04 00 00 } //25 3b 
	condition:
		any of ($a_*)
 
}