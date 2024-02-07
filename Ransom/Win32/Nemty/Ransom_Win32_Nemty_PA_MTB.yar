
rule Ransom_Win32_Nemty_PA_MTB{
	meta:
		description = "Ransom:Win32/Nemty.PA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 6e 65 6d 74 79 2e 65 78 65 } //01 00  \nemty.exe
		$a_01_1 = {2d 44 45 43 52 59 50 54 2e 74 78 74 } //01 00  -DECRYPT.txt
		$a_01_2 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //01 00  vssadmin.exe delete shadows /all /quiet
		$a_01_3 = {66 75 63 6b 61 76 } //00 00  fuckav
	condition:
		any of ($a_*)
 
}