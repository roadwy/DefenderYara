
rule Trojan_Win64_WingoObfus_NH_MTB{
	meta:
		description = "Trojan:Win64/WingoObfus.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 6f 77 36 34 53 65 74 5f 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 Wow64Set_ThreadContext
		$a_01_1 = {47 65 74 4e 54 48 64 72 73 } //1 GetNTHdrs
		$a_01_2 = {41 6c 6c 6f 63 50 45 42 75 66 66 65 72 } //1 AllocPEBuffer
		$a_01_3 = {6d 61 69 6e 2e 52 65 64 69 72 65 63 74 54 6f 50 61 79 6c 6f 61 64 } //1 main.RedirectToPayload
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}