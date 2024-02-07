
rule Trojan_Win32_Redline_DAA_MTB{
	meta:
		description = "Trojan:Win32/Redline.DAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 53 4c 74 4c 51 53 78 74 76 70 64 42 45 43 55 5a 42 58 6b 61 65 54 50 6c 77 53 64 67 4c } //01 00  oSLtLQSxtvpdBECUZBXkaeTPlwSdgL
		$a_01_1 = {4b 79 49 52 64 76 42 64 42 73 68 44 47 7a 55 71 70 47 4a 68 65 56 62 4f 42 61 45 44 48 44 } //01 00  KyIRdvBdBshDGzUqpGJheVbOBaEDHD
		$a_01_2 = {74 58 61 79 58 5a 79 46 41 6c 77 4b 58 44 79 45 77 69 61 62 4f 55 } //01 00  tXayXZyFAlwKXDyEwiabOU
		$a_01_3 = {4f 44 6a 55 6f 78 42 59 4c 61 78 6d 66 6d 4b 4f 6c 62 63 59 67 4b 6b 71 43 } //01 00  ODjUoxBYLaxmfmKOlbcYgKkqC
		$a_01_4 = {65 43 70 6d 4d 44 6c 48 56 59 48 63 67 69 6d 72 77 6d 57 48 66 54 46 48 4a 62 71 63 7a 49 6f } //01 00  eCpmMDlHVYHcgimrwmWHfTFHJbqczIo
		$a_01_5 = {51 77 74 55 51 4a 62 4a 78 72 6f 75 71 47 7a 42 72 6d 74 58 4d 45 72 47 76 63 55 74 45 5a 75 } //01 00  QwtUQJbJxrouqGzBrmtXMErGvcUtEZu
		$a_01_6 = {6c 50 43 6f 4d 49 52 71 65 55 66 58 4f 75 65 58 56 74 41 78 6d 78 74 55 55 75 4e 70 64 67 } //00 00  lPCoMIRqeUfXOueXVtAxmxtUUuNpdg
	condition:
		any of ($a_*)
 
}