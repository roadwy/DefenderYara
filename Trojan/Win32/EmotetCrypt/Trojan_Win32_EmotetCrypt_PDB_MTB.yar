
rule Trojan_Win32_EmotetCrypt_PDB_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 01 0f b6 13 03 c2 99 b9 ?? ?? ?? ?? f7 f9 a1 ?? ?? ?? ?? 46 0f b6 d2 8a 0c 02 8b 44 24 ?? 30 4c 30 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}