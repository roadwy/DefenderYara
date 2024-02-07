
rule Ransom_Win32_Filecoder_DG_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {2e 72 61 70 69 64 } //01 00  .rapid
		$a_81_1 = {21 20 48 6f 77 20 44 65 63 72 79 70 74 20 46 69 6c 65 73 2e 74 78 74 } //01 00  ! How Decrypt Files.txt
		$a_81_2 = {44 65 63 72 79 70 74 65 64 64 21 } //01 00  Decryptedd!
		$a_81_3 = {54 65 73 74 20 65 6e 63 72 79 70 74 20 66 61 69 6c 65 64 } //00 00  Test encrypt failed
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Filecoder_DG_MTB_2{
	meta:
		description = "Ransom:Win32/Filecoder.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {2e 67 75 65 73 73 77 68 6f } //01 00  .guesswho
		$a_81_1 = {54 65 73 74 20 64 65 63 72 79 70 74 20 66 61 69 6c 65 64 } //01 00  Test decrypt failed
		$a_81_2 = {44 45 43 52 59 50 54 45 44 } //01 00  DECRYPTED
		$a_81_3 = {48 6f 77 20 52 65 63 6f 76 65 72 79 20 46 69 6c 65 73 2e 74 78 74 } //00 00  How Recovery Files.txt
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Filecoder_DG_MTB_3{
	meta:
		description = "Ransom:Win32/Filecoder.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_81_0 = {2f 63 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //02 00  /c vssadmin.exe Delete Shadows /All /Quiet
		$a_81_1 = {2e 72 61 70 69 64 } //01 00  .rapid
		$a_81_2 = {48 6f 77 20 52 65 63 6f 76 65 72 79 20 46 69 6c 65 73 2e 74 78 74 } //01 00  How Recovery Files.txt
		$a_81_3 = {72 61 70 69 64 40 61 69 72 6d 61 69 6c 2e 63 63 } //00 00  rapid@airmail.cc
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Filecoder_DG_MTB_4{
	meta:
		description = "Ransom:Win32/Filecoder.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d } //01 00  -----BEGIN PUBLIC KEY-----
		$a_81_1 = {2d 2d 2d 2d 2d 45 4e 44 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d } //01 00  -----END PUBLIC KEY-----
		$a_81_2 = {53 43 48 54 41 53 4b 53 20 2f 44 45 4c 45 54 45 20 2f 54 4e 20 } //01 00  SCHTASKS /DELETE /TN 
		$a_81_3 = {6e 65 74 77 6f 72 6b 61 75 74 6f 2e 74 6f 70 } //01 00  networkauto.top
		$a_81_4 = {67 61 74 65 2e 70 68 70 } //00 00  gate.php
	condition:
		any of ($a_*)
 
}