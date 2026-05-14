
rule Trojan_Win64_Apshee_GVA_MTB{
	meta:
		description = "Trojan:Win64/Apshee.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 77 77 77 2e 69 62 73 65 6e 73 6f 66 74 77 61 72 65 2e 63 6f 6d 2f } //1 ://www.ibsensoftware.com/
		$a_01_1 = {47 65 74 57 69 6e 64 6f 77 54 68 72 65 61 64 50 72 6f 63 65 73 73 49 64 } //1 GetWindowThreadProcessId
		$a_01_2 = {52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 43 74 72 6c 48 61 6e 64 6c 65 72 57 } //1 RegisterServiceCtrlHandlerW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}