
rule Trojan_Win32_SmokeLoader_EAHT_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.EAHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e8 05 03 44 24 28 03 cd 33 c1 8d 0c 3b 33 c1 2b f0 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}