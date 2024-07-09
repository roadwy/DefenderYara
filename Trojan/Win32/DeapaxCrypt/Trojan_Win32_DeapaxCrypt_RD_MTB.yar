
rule Trojan_Win32_DeapaxCrypt_RD_MTB{
	meta:
		description = "Trojan:Win32/DeapaxCrypt.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 ea cc 34 00 00 89 55 [0-05] 8b 45 [0-05] 33 [0-07] 89 45 [0-05] 8b 4d [0-05] 8b 95 ?? ?? ?? ?? 8b 45 [0-05] 89 04 8a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}