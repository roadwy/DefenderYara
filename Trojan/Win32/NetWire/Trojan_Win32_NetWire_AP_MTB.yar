
rule Trojan_Win32_NetWire_AP_MTB{
	meta:
		description = "Trojan:Win32/NetWire.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {8d 43 01 0f b6 d8 8a 54 1c 14 0f b6 c2 03 c5 0f b6 e8 8b 44 24 10 8a 4c 2c 14 88 4c 1c 14 02 ca 0f b6 c9 88 54 2c 14 0f b6 4c 0c 14 30 0c 07 47 3b fe 7c } //3
		$a_01_1 = {4d 54 5f 71 55 44 72 6a 5c 46 34 59 30 57 36 57 38 35 5c 55 34 52 53 57 67 36 5c 50 51 30 30 64 52 35 7a 64 30 36 34 57 52 } //1 MT_qUDrj\F4Y0W6W85\U4RSWg6\PQ00dR5zd064WR
		$a_01_2 = {73 51 30 73 69 64 5c 43 59 59 57 51 52 35 36 2e 66 6c 69 } //1 sQ0sid\CYYWQR56.fli
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}