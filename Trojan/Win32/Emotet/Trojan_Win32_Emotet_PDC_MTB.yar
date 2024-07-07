
rule Trojan_Win32_Emotet_PDC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {81 e1 ff 00 00 00 03 c1 b9 90 01 04 99 f7 f9 8a 45 00 8a 94 14 90 01 04 32 c2 88 45 00 90 00 } //1
		$a_81_1 = {4d 39 4c 30 72 6d 62 32 42 73 67 45 36 57 73 48 59 31 44 45 71 72 34 7a 71 55 47 53 71 42 67 38 6e } //1 M9L0rmb2BsgE6WsHY1DEqr4zqUGSqBg8n
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}