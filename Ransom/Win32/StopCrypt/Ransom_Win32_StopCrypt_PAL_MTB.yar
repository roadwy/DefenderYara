
rule Ransom_Win32_StopCrypt_PAL_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 10 89 45 ?? 8b 45 0c 31 45 ?? 8b 45 ?? 8b 4d 08 89 01 [0-02] c9 c2 0c 00 81 00 03 35 ef c6 c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}