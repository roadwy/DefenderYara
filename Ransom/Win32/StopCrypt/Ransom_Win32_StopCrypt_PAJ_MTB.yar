
rule Ransom_Win32_StopCrypt_PAJ_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 6a 00 68 [0-04] ff [0-06] 83 65 [0-02] 8b 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 8b 4d 08 89 01 c9 c2 [0-02] 81 00 03 35 ef c6 c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}