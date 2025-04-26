
rule Ransom_Win32_StopCrypt_VID_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.VID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 8b 45 c0 83 c0 64 89 45 ?? 83 6d c4 64 8a 4d c4 30 0c 33 83 ff 0f 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}