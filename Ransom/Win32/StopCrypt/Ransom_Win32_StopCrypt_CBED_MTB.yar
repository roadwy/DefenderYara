
rule Ransom_Win32_StopCrypt_CBED_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.CBED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 dc 01 45 fc 8b 4d f8 8d 04 ?? 31 45 fc d3 ?? 03 ?? ?? 81 3d } //1
		$a_03_1 = {31 7d fc 8b 45 fc 29 45 f4 81 c3 ?? ?? ?? ?? ff 4d e8 0f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}