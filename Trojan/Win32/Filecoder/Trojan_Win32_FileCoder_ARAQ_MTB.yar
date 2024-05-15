
rule Trojan_Win32_FileCoder_ARAQ_MTB{
	meta:
		description = "Trojan:Win32/FileCoder.ARAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 79 73 74 65 6d 20 69 73 20 65 6e 63 72 79 70 74 65 64 20 42 79 20 52 41 4e 53 4f 4d 43 52 59 50 54 4f } //02 00  system is encrypted By RANSOMCRYPTO
		$a_01_1 = {3a 2f 2f 52 61 6e 73 6f 6d 43 72 79 70 74 6f 5f 71 6f 69 61 36 45 31 46 6b 6f 51 6a 65 66 41 39 69 61 31 30 2e 6f 6e 69 6f 6e } //00 00  ://RansomCrypto_qoia6E1FkoQjefA9ia10.onion
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_FileCoder_ARAQ_MTB_2{
	meta:
		description = "Trojan:Win32/FileCoder.ARAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {40 00 54 00 41 00 4e 00 4b 00 49 00 58 00 2e 00 } //02 00  @TANKIX.
		$a_01_1 = {5c 00 42 00 53 00 4f 00 44 00 2e 00 65 00 78 00 65 00 } //02 00  \BSOD.exe
		$a_01_2 = {64 00 35 00 61 00 30 00 31 00 73 00 39 00 75 00 } //02 00  d5a01s9u
		$a_01_3 = {45 00 6e 00 61 00 62 00 6c 00 65 00 4c 00 55 00 41 00 } //02 00  EnableLUA
		$a_01_4 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //00 00  DisableTaskMgr
	condition:
		any of ($a_*)
 
}