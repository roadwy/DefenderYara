
rule Trojan_Win32_Fragtor_AG_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 0c 27 23 c0 33 cb 66 25 10 91 8b d0 41 42 0f 8c 01 99 eb ff 48 c7 44 24 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}