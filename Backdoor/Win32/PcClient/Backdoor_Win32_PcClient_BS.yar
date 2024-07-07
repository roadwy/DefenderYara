
rule Backdoor_Win32_PcClient_BS{
	meta:
		description = "Backdoor:Win32/PcClient.BS,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {69 00 6d 00 61 00 67 00 65 00 2f 00 67 00 69 00 66 00 00 00 69 00 6d 00 61 00 67 00 65 00 2f 00 6a 00 70 00 65 00 67 00 } //1
		$a_02_1 = {c6 85 00 fc ff ff 49 c6 85 01 fc ff ff 65 c6 85 02 fc ff ff 78 c6 85 03 fc ff ff 70 c6 85 04 fc ff ff 6c c6 85 05 fc ff ff 6f c6 85 06 fc ff ff 72 c6 85 07 fc ff ff 65 c6 85 08 fc ff ff 2e c6 85 09 fc ff ff 65 c6 85 0a fc ff ff 78 c6 85 0b fc ff ff 65 0f be 8d 00 fe ff ff 83 e9 30 f7 d9 1b c9 83 e1 fb 83 c1 05 51 6a 00 8d 95 01 fe ff ff 52 8d 85 00 fc ff ff 50 6a 00 6a 00 ff 15 90 01 04 5f 5e 5b 8b e5 5d c3 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}