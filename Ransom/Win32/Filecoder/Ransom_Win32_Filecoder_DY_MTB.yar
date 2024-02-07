
rule Ransom_Win32_Filecoder_DY_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 52 65 73 74 6f 72 65 5c 53 52 22 20 2f 64 69 73 61 62 6c 65 } //01 00  \Microsoft\Windows\SystemRestore\SR" /disable
		$a_81_1 = {2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 62 6f 6f 74 73 74 61 74 75 73 70 6f 6c 69 63 79 20 69 67 6e 6f 72 65 61 6c 6c 66 61 69 6c 75 72 65 73 } //01 00  /set {default} bootstatuspolicy ignoreallfailures
		$a_81_2 = {2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6e 6f } //01 00  /set {default} recoveryenabled no
		$a_81_3 = {64 65 6c 65 74 65 20 63 61 74 61 6c 6f 67 20 2d 71 75 69 65 74 } //01 00  delete catalog -quiet
		$a_81_4 = {63 69 70 68 65 72 2e 65 78 65 } //01 00  cipher.exe
		$a_81_5 = {6e 63 72 79 70 74 69 6f 6e } //00 00  ncryption
	condition:
		any of ($a_*)
 
}