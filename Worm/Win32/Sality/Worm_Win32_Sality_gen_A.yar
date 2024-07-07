
rule Worm_Win32_Sality_gen_A{
	meta:
		description = "Worm:Win32/Sality.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4d 0f 85 31 01 00 00 0f be 90 01 01 d8 f6 ff ff 83 90 01 01 5a 0f 85 21 01 00 00 83 bd e8 f6 ff ff 02 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}