
rule Ransom_Win32_FileEncoder_YBE_MTB{
	meta:
		description = "Ransom:Win32/FileEncoder.YBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 fa 01 ca 70 17 8a 5c 0d a8 30 1c 16 41 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}