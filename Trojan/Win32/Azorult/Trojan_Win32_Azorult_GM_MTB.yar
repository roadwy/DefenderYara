
rule Trojan_Win32_Azorult_GM_MTB{
	meta:
		description = "Trojan:Win32/Azorult.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 ff 69 04 00 00 90 02 10 30 04 33 90 02 10 8d 44 24 90 01 02 8d 4c 24 90 02 06 8d 54 24 90 02 10 46 3b f7 7c 90 00 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}