
rule Trojan_Win32_Stresid_gen_F{
	meta:
		description = "Trojan:Win32/Stresid.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 07 57 ba 90 01 03 00 e8 90 01 02 00 00 50 8d 4d c8 e8 90 01 02 00 00 3b c7 0f 8c 90 01 02 00 00 66 83 8d 28 ff ff ff ff 66 c7 85 20 ff ff ff 0b 00 51 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}