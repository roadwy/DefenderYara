
rule Trojan_Win32_Vbcrypt_EA{
	meta:
		description = "Trojan:Win32/Vbcrypt.EA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {38 00 42 00 34 00 43 00 32 00 34 00 30 00 38 00 35 00 31 00 3c 00 70 00 31 00 3e 00 45 00 38 00 3c 00 70 00 32 00 3e 00 35 00 39 00 38 00 39 00 30 00 31 00 36 00 36 00 33 00 31 00 43 00 30 00 43 00 33 00 } //01 00  8B4C240851<p1>E8<p2>5989016631C0C3
		$a_01_1 = {44 65 76 65 6b 20 53 6f 66 74 77 61 72 65 } //01 00  Devek Software
		$a_01_2 = {43 61 72 00 66 69 6c 65 58 } //00 00 
	condition:
		any of ($a_*)
 
}