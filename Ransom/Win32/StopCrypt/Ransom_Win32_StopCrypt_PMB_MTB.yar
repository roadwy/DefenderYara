
rule Ransom_Win32_StopCrypt_PMB_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 45 0c c1 ea 90 01 01 03 55 e8 50 c7 05 90 02 08 e8 90 02 04 31 55 0c 2b 5d 0c 68 b9 79 37 9e 8d 45 fc 50 e8 90 02 04 ff 4d f8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}