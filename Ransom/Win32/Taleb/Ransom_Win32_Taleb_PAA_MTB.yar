
rule Ransom_Win32_Taleb_PAA_MTB{
	meta:
		description = "Ransom:Win32/Taleb.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6e 6f } //01 00  bcdedit /set {default} recoveryenabled no
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 70 72 76 6b 65 79 2e 74 78 74 } //01 00  C:\ProgramData\prvkey.txt
		$a_01_2 = {66 75 63 6b 79 6f 75 66 75 63 6b 79 6f 75 } //01 00  fuckyoufuckyou
		$a_01_3 = {46 00 69 00 6c 00 65 00 73 00 20 00 48 00 61 00 73 00 20 00 42 00 65 00 65 00 6e 00 20 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //00 00  Files Has Been Encrypted
		$a_00_4 = {5d 04 00 } //00 66 
	condition:
		any of ($a_*)
 
}