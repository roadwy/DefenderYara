
rule PWS_Win32_Phishack_C{
	meta:
		description = "PWS:Win32/Phishack.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {57 00 65 00 62 00 4d 00 6f 00 6e 00 65 00 79 00 48 00 61 00 63 00 6b 00 00 90 09 1a 00 43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 90 00 } //01 00 
		$a_01_1 = {2e 73 6f 75 6c 73 74 72 65 61 6d 2e 72 75 } //00 00  .soulstream.ru
	condition:
		any of ($a_*)
 
}