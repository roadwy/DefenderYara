
rule Ransom_Win32_Cerber_YAB_MTB{
	meta:
		description = "Ransom:Win32/Cerber.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 84 95 d8 fb ff ff 88 85 ?? ?? ?? ?? 8b 4d 08 03 4d dc 0f b6 11 0f b6 85 93 fb ff ff 33 d0 8b 4d 08 03 4d dc 88 11 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}