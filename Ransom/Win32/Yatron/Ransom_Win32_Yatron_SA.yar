
rule Ransom_Win32_Yatron_SA{
	meta:
		description = "Ransom:Win32/Yatron.SA,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 74 75 62 20 6a 32 2e 65 78 65 } //01 00  stub j2.exe
		$a_01_1 = {63 5f 41 6e 74 69 4b 69 6c 6c } //01 00  c_AntiKill
		$a_01_2 = {45 6e 63 72 79 70 74 46 69 6c 65 } //01 00  EncryptFile
		$a_01_3 = {46 75 63 6b 5f 61 6c 6c } //01 00  Fuck_all
		$a_01_4 = {59 00 61 00 74 00 72 00 6f 00 6e 00 } //00 00  Yatron
	condition:
		any of ($a_*)
 
}