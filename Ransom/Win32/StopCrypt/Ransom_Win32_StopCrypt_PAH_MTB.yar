
rule Ransom_Win32_StopCrypt_PAH_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 04 8b 4c 24 08 29 08 c2 [0-02] 8b 44 24 04 8b 4c 24 08 29 08 c2 [0-02] 55 8b ec 51 83 65 fc ?? 8b 45 ?? 01 45 ?? 8b 45 08 8b 4d ?? 31 08 c9 c2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}