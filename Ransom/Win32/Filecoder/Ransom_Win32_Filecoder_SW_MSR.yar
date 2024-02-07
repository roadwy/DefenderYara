
rule Ransom_Win32_Filecoder_SW_MSR{
	meta:
		description = "Ransom:Win32/Filecoder.SW!MSR,SIGNATURE_TYPE_PEHSTR_EXT,2c 00 2c 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 00 6f 00 72 00 20 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 } //01 00  tor browser
		$a_00_1 = {63 00 79 00 6e 00 65 00 74 00 20 00 72 00 61 00 6e 00 73 00 6f 00 6d 00 20 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 28 00 64 00 6f 00 6e 00 27 00 74 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 29 00 } //0a 00  cynet ransom protection(don't delete)
		$a_01_2 = {45 6e 63 72 79 70 74 44 69 73 6b 28 25 77 73 29 20 44 4f 4e 45 } //0a 00  EncryptDisk(%ws) DONE
		$a_01_3 = {59 6f 75 72 20 6e 65 74 77 6f 72 6b 20 69 73 20 70 65 6e 65 74 72 61 74 65 64 } //01 00  Your network is penetrated
		$a_01_4 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 68 } //0a 00  @protonmail.ch
		$a_01_5 = {6d 61 6c 6c 79 40 6d 61 69 6c 66 65 6e 63 65 2e 63 6f 6d } //01 00  mally@mailfence.com
		$a_01_6 = {66 61 6b 65 2e 70 64 62 } //0a 00  fake.pdb
		$a_01_7 = {72 61 6e 73 6f 6d 77 61 72 65 2e 65 78 65 } //00 00  ransomware.exe
		$a_00_8 = {5d 04 00 00 7b 6a 04 80 5c 3a 00 00 7c 6a 04 80 00 00 01 00 04 00 24 00 54 72 6f 6a 61 6e 44 6f 77 6e 6c 6f 61 64 65 72 } //3a 4f 
	condition:
		any of ($a_*)
 
}