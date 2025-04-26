
rule Trojan_Win32_MetaStealer_AT_MTB{
	meta:
		description = "Trojan:Win32/MetaStealer.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {54 61 73 6b 4d 61 6e 61 67 65 72 40 73 74 65 61 6c 65 72 } //1 TaskManager@stealer
		$a_81_1 = {72 61 74 5c 63 6c 69 65 6e 74 5c 73 74 65 61 6c 65 72 } //1 rat\client\stealer
		$a_81_2 = {4c 69 73 74 65 6e 40 } //1 Listen@
		$a_81_3 = {24 61 6c 6c 6f 63 61 74 6f 72 40 } //1 $allocator@
		$a_81_4 = {73 74 65 61 6c 65 72 74 65 73 74 2e 64 6c 6c } //1 stealertest.dll
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}