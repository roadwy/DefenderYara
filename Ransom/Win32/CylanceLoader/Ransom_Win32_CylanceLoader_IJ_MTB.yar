
rule Ransom_Win32_CylanceLoader_IJ_MTB{
	meta:
		description = "Ransom:Win32/CylanceLoader.IJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 30 22 40 00 6a 01 33 f6 56 ff 15 2c 20 40 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}