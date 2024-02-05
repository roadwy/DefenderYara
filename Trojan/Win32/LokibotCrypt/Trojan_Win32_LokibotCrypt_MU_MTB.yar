
rule Trojan_Win32_LokibotCrypt_MU_MTB{
	meta:
		description = "Trojan:Win32/LokibotCrypt.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 ff 16 05 00 00 90 18 46 3b f7 90 18 e8 90 01 04 30 90 00 } //01 00 
		$a_02_1 = {55 8b ec 51 90 02 04 53 b8 90 02 04 8b 90 02 05 01 90 02 02 01 90 02 02 8b 90 02 02 8a 90 02 02 8b 90 02 05 88 90 02 05 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}