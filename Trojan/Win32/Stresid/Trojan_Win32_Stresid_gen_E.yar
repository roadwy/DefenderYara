
rule Trojan_Win32_Stresid_gen_E{
	meta:
		description = "Trojan:Win32/Stresid.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 07 57 ba 90 01 03 00 e8 90 01 02 00 00 50 8d 4d 10 e8 90 01 02 ff ff 3b c7 0f 8c 90 01 02 00 00 66 83 4d 9c ff 66 c7 45 94 0b 00 51 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}