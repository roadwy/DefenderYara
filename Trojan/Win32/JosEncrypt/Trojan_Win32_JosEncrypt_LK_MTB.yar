
rule Trojan_Win32_JosEncrypt_LK_MTB{
	meta:
		description = "Trojan:Win32/JosEncrypt.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 6c 65 61 73 65 5c 46 75 6c 6c 53 74 61 72 74 2e 70 64 62 } //01 00  Release\FullStart.pdb
		$a_01_1 = {52 00 45 00 43 00 4f 00 56 00 45 00 52 00 59 00 2e 00 74 00 78 00 74 00 } //01 00  RECOVERY.txt
		$a_01_2 = {59 00 4f 00 55 00 52 00 20 00 4b 00 45 00 59 00 3a 00 } //01 00  YOUR KEY:
		$a_01_3 = {2e 00 6a 00 6f 00 73 00 65 00 70 00 } //01 00  .josep
		$a_01_4 = {68 10 27 00 00 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}