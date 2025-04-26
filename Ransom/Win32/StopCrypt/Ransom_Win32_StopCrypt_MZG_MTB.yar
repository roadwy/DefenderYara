
rule Ransom_Win32_StopCrypt_MZG_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MZG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 45 fc 8b 45 fc 8b 4d 08 89 01 5e c9 c2 [0-02] 33 44 24 04 c2 [0-02] 81 00 [0-04] c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}