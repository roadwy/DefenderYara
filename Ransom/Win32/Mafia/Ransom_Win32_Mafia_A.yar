
rule Ransom_Win32_Mafia_A{
	meta:
		description = "Ransom:Win32/Mafia.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 77 63 68 6f 73 74 2e 65 78 65 } //1 swchost.exe
		$a_01_1 = {6f 6e 69 6f 6e 2e } //1 onion.
		$a_01_2 = {2f 6d 61 66 69 61 45 67 6e 69 6d 61 2e 70 68 70 } //1 /mafiaEgnima.php
		$a_01_3 = {2e 4d 41 46 49 41 } //1 .MAFIA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}