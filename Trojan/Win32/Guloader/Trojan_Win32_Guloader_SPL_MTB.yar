
rule Trojan_Win32_Guloader_SPL_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 6e 73 71 75 65 61 6d 69 73 68 6e 65 73 73 31 } //01 00  Unsqueamishness1
		$a_01_1 = {53 69 73 74 65 6e 63 65 20 54 61 6e 61 6e 20 57 61 6b 65 72 20 31 } //01 00  Sistence Tanan Waker 1
		$a_01_2 = {41 6e 6e 6c 69 6c 73 40 53 74 65 6e 63 65 73 2e 56 65 30 } //01 00  Annlils@Stences.Ve0
		$a_01_3 = {41 6e 6e 6c 69 6c 73 40 53 74 65 6e 63 65 73 2e 56 65 } //00 00  Annlils@Stences.Ve
	condition:
		any of ($a_*)
 
}