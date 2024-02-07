
rule Ransom_Win32_VhdLocker_PA_MTB{
	meta:
		description = "Ransom:Win32/VhdLocker.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 76 00 68 00 64 00 } //01 00  .vhd
		$a_00_1 = {73 63 20 73 74 6f 70 20 22 4d 69 63 72 6f 73 6f 66 74 20 45 78 63 68 61 6e 67 65 } //01 00  sc stop "Microsoft Exchange
		$a_01_2 = {48 00 6f 00 77 00 54 00 6f 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 2e 00 74 00 78 00 74 00 } //01 00  HowToDecrypt.txt
		$a_01_3 = {41 00 45 00 45 00 41 00 45 00 45 00 20 00 53 00 45 00 54 00 } //00 00  AEEAEE SET
	condition:
		any of ($a_*)
 
}