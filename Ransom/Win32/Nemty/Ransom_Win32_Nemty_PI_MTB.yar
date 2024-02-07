
rule Ransom_Win32_Nemty_PI_MTB{
	meta:
		description = "Ransom:Win32/Nemty.PI!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 45 4d 54 59 } //01 00  NEMTY
		$a_01_1 = {62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6e 6f } //01 00  bcdedit /set {default} recoveryenabled no
		$a_01_2 = {77 6d 69 63 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //01 00  wmic shadowcopy delete
		$a_01_3 = {2d 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 2e 00 74 00 78 00 74 00 } //00 00  -DECRYPT.txt
	condition:
		any of ($a_*)
 
}