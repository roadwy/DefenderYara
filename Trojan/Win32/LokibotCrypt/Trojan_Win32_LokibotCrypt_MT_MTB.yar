
rule Trojan_Win32_LokibotCrypt_MT_MTB{
	meta:
		description = "Trojan:Win32/LokibotCrypt.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 04 0a 41 3b ce 90 18 90 18 55 8b ec ?? a1 [0-10] a3 [0-04] 81 [0-06] 8b [0-03] 01 [0-05] 0f [0-06] 25 [0-08] c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}