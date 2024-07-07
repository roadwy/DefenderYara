
rule Backdoor_Win32_Usinec_A{
	meta:
		description = "Backdoor:Win32/Usinec.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 00 ff d0 69 de 90 01 02 00 00 89 84 1d 90 01 02 ff ff 89 bc 1d 90 01 02 ff ff 89 bc 1d 90 01 02 ff ff 90 02 10 8d 45 fc 50 a1 90 01 04 8b 00 b9 06 00 00 00 ba 01 00 00 00 90 00 } //1
		$a_03_1 = {6a 00 6a 00 68 1f 00 0f 00 53 a1 90 01 04 8b 00 ff d0 a3 90 01 04 83 3d 90 1b 01 00 74 90 02 09 8b c6 b9 90 01 02 00 00 8b 15 90 1b 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}