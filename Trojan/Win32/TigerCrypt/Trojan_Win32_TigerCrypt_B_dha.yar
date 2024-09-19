
rule Trojan_Win32_TigerCrypt_B_dha{
	meta:
		description = "Trojan:Win32/TigerCrypt.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_43_0 = {d0 07 00 00 66 90 90 6a 40 68 00 10 00 00 68 10 27 00 00 6a 00 ff 90 01 01 6a 01 8b f0 ff 15 90 01 04 68 00 80 00 00 6a 00 56 ff 90 00 00 } //100
	condition:
		((#a_43_0  & 1)*100) >=100
 
}