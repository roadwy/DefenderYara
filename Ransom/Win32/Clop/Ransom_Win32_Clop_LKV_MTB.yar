
rule Ransom_Win32_Clop_LKV_MTB{
	meta:
		description = "Ransom:Win32/Clop.LKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d 20 4d 49 47 66 4d 41 30 47 43 53 71 47 53 49 62 33 44 51 45 42 41 51 55 41 41 34 47 4e 41 44 43 42 69 51 4b 42 67 51 } //01 00  -----BEGIN PUBLIC KEY----- MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ
		$a_01_1 = {2e 00 43 00 49 00 6f 00 70 00 } //01 00  .CIop
		$a_01_2 = {2e 00 43 00 6c 00 30 00 70 00 } //01 00  .Cl0p
		$a_01_3 = {2e 00 43 00 5f 00 4c 00 5f 00 4f 00 5f 00 50 00 } //01 00  .C_L_O_P
		$a_01_4 = {72 00 75 00 6e 00 72 00 75 00 6e 00 } //01 00  runrun
		$a_01_5 = {74 00 65 00 6d 00 70 00 2e 00 6f 00 63 00 78 00 } //01 00  temp.ocx
		$a_01_6 = {43 00 49 00 6f 00 70 00 52 00 65 00 61 00 64 00 4d 00 65 00 2e 00 74 00 78 00 74 00 } //01 00  CIopReadMe.txt
		$a_01_7 = {43 00 6c 00 30 00 70 00 52 00 65 00 61 00 64 00 4d 00 65 00 2e 00 74 00 78 00 74 00 } //00 00  Cl0pReadMe.txt
	condition:
		any of ($a_*)
 
}