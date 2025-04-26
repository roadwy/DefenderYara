
rule Ransom_Win32_QilinDecryptor_YTD_MTB{
	meta:
		description = "Ransom:Win32/QilinDecryptor.YTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 5c 10 ff 8b 75 08 30 1c 0e 41 3b 55 d0 73 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}