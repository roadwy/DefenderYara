
rule TrojanSpy_Win32_Banker_NN{
	meta:
		description = "TrojanSpy:Win32/Banker.NN,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {5e 5b c3 ff ff ff ff 0f 00 00 00 63 3a 5c 73 79 73 74 65 6d 33 32 2e 67 69 66 00 ff ff ff ff [0-20] 68 74 74 70 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}