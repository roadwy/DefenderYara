
rule Trojan_Win64_TigerCrypt_C_dha{
	meta:
		description = "Trojan:Win64/TigerCrypt.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 f7 49 00 00 48 8b d3 48 8d 4c 24 38 e8 ba 2d 00 00 48 8b d0 48 8d 4c 24 20 e8 ed 2e 00 00 48 8d 54 24 20 48 8d 4c 24 38 e8 4e } //100
	condition:
		((#a_01_0  & 1)*100) >=100
 
}