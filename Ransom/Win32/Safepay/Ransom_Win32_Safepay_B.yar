
rule Ransom_Win32_Safepay_B{
	meta:
		description = "Ransom:Win32/Safepay.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2d 00 73 00 2d 00 6e 00 65 00 74 00 64 00 72 00 69 00 76 00 65 00 00 00 2d 00 70 00 61 00 73 00 73 00 3d 00 00 00 2d 00 65 00 6e 00 63 00 3d 00 00 00 2d 00 6c 00 6f 00 67 00 00 00 2d 00 75 00 61 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}