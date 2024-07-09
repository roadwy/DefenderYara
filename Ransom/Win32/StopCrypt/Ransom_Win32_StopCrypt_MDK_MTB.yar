
rule Ransom_Win32_StopCrypt_MDK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 08 8b 4d 0c 33 08 8b 55 08 89 0a 5d c2 } //1
		$a_03_1 = {55 8b ec 51 c7 45 fc [0-04] 8b 45 0c 8b 4d fc d3 e0 8b 4d 08 89 01 8b e5 5d c2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}