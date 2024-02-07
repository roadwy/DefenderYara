
rule Trojan_BAT_RedLineStealer_MLA_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 49 37 68 43 74 37 5a 67 77 78 } //01 00  FI7hCt7Zgwx
		$a_01_1 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_2 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_3 = {4d 61 72 73 68 61 6c 43 6f 6f 6b 69 65 49 73 50 65 72 73 69 73 74 65 6e 74 } //01 00  MarshalCookieIsPersistent
		$a_01_4 = {46 69 6c 65 57 72 69 74 61 62 6c 65 54 79 70 65 49 41 } //01 00  FileWritableTypeIA
		$a_01_5 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d 49 4e 56 4f 4b 45 } //01 00  MemoryStreamINVOKE
		$a_01_6 = {53 6f 61 70 53 65 72 76 69 63 65 73 73 65 74 4b 65 79 50 61 73 73 77 6f 72 64 } //01 00  SoapServicessetKeyPassword
		$a_01_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggableAttribute
	condition:
		any of ($a_*)
 
}