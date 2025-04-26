
rule Trojan_BAT_KeyLogger_RDF_MTB{
	meta:
		description = "Trojan:BAT/KeyLogger.RDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {62 66 35 30 36 61 37 35 2d 63 64 31 39 2d 34 33 33 33 2d 38 38 32 63 2d 32 36 35 63 61 38 34 35 34 63 39 37 } //1 bf506a75-cd19-4333-882c-265ca8454c97
		$a_01_1 = {4b 65 79 4c 6f 67 67 65 72 } //1 KeyLogger
		$a_01_2 = {4c 6f 77 4c 65 76 65 6c 4b 65 79 62 6f 61 72 64 50 72 6f 63 } //1 LowLevelKeyboardProc
		$a_01_3 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //1 CallNextHookEx
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}