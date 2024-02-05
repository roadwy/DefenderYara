
rule Trojan_Win32_LokibotCrypt_MT_MTB{
	meta:
		description = "Trojan:Win32/LokibotCrypt.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {30 04 0a 41 3b ce 90 18 90 18 55 8b ec 90 01 01 a1 90 02 10 a3 90 02 04 81 90 02 06 8b 90 02 03 01 90 02 05 0f 90 02 06 25 90 02 08 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}