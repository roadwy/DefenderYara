
rule Ransom_Win32_Cerber_YAA_MTB{
	meta:
		description = "Ransom:Win32/Cerber.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 85 ec fb ff ff 03 45 f8 0f b6 08 0f b6 95 f2 fb ff ff 33 ca 8b 85 ec fb ff ff 03 45 f8 88 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}