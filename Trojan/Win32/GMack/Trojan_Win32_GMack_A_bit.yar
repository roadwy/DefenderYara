
rule Trojan_Win32_GMack_A_bit{
	meta:
		description = "Trojan:Win32/GMack.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {67 75 70 72 6f 63 68 65 61 74 2e 6e 65 74 2f [0-2f] 42 75 67 54 72 61 70 2e 65 78 65 } //1
		$a_01_1 = {50 6f 69 6e 74 42 6c 61 6e 6b 2e 65 78 65 } //1 PointBlank.exe
		$a_01_2 = {42 75 67 54 72 61 70 2e 70 64 62 } //1 BugTrap.pdb
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}