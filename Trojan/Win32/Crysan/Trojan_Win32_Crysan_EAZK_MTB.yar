
rule Trojan_Win32_Crysan_EAZK_MTB{
	meta:
		description = "Trojan:Win32/Crysan.EAZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 01 d0 31 cb 89 da 88 10 83 45 f8 01 8b 45 f8 3b 45 18 72 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}