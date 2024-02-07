
rule Trojan_Win32_Emotet_S_MSR{
	meta:
		description = "Trojan:Win32/Emotet.S!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {6d 66 63 63 61 6c 63 2e 63 61 6c 63 75 6c 61 74 6f 72 } //02 00  mfccalc.calculator
		$a_01_1 = {46 00 55 00 43 00 4b 00 20 00 45 00 53 00 45 00 54 00 } //01 00  FUCK ESET
		$a_01_2 = {25 73 5c 73 68 65 6c 6c 5c 70 72 69 6e 74 } //01 00  %s\shell\print
		$a_01_3 = {45 6e 63 72 79 70 74 44 61 74 61 } //01 00  EncryptData
		$a_01_4 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //01 00  IsProcessorFeaturePresent
		$a_01_5 = {43 00 72 00 79 00 70 00 74 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 } //00 00  CryptEncrypt
	condition:
		any of ($a_*)
 
}