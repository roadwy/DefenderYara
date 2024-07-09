
rule Trojan_Win32_LokibotCrypt_MR_MTB{
	meta:
		description = "Trojan:Win32/LokibotCrypt.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {3b c7 7c c3 90 0a 41 00 69 [0-05] 89 [0-05] 89 [0-05] 81 [0-09] 8b [0-05] 03 [0-05] 40 89 [0-05] 8a [0-05] 30 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}