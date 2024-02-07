
rule Trojan_Win32_Ursnif_SB{
	meta:
		description = "Trojan:Win32/Ursnif.SB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 59 61 72 64 5c 42 61 6c 6c 5c 50 61 69 72 5c 64 69 66 66 69 63 75 6c 74 68 61 73 2e 70 64 62 } //02 00  c:\Yard\Ball\Pair\difficulthas.pdb
		$a_01_1 = {64 65 4d 75 69 61 65 72 } //00 00  deMuiaer
	condition:
		any of ($a_*)
 
}