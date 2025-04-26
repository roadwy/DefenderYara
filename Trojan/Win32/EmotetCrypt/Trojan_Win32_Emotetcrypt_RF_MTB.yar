
rule Trojan_Win32_Emotetcrypt_RF_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 ab aa aa aa f7 e1 8b c3 83 c3 06 c1 ea 03 8d 0c 52 c1 e1 02 2b c1 0f b6 44 85 ?? 30 47 ?? 81 fb 00 34 02 00 0f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}