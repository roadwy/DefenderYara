
rule Ransom_Win32_Zorba_AA_MTB{
	meta:
		description = "Ransom:Win32/Zorba.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 5a 4f 52 41 42 20 3d } //01 00  = ZORAB =
		$a_01_1 = {59 6f 75 72 20 64 6f 63 75 6d 65 6e 74 73 2c 20 70 68 6f 74 6f 73 2c 20 64 61 74 61 62 61 73 65 73 20 61 6e 64 20 6f 74 68 65 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 61 6e 64 20 68 61 76 65 20 74 68 65 20 65 78 74 65 6e 73 69 6f 6e 3a 20 2e 5a 52 42 } //00 00  Your documents, photos, databases and other important files are encrypted and have the extension: .ZRB
	condition:
		any of ($a_*)
 
}