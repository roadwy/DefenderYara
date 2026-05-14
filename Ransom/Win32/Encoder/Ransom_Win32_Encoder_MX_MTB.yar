
rule Ransom_Win32_Encoder_MX_MTB{
	meta:
		description = "Ransom:Win32/Encoder.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 83 c4 0c 48 a3 fc 44 01 02 89 35 00 45 01 02 33 c0 eb 03 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}