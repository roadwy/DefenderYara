
rule Trojan_Win32_Diple_GMA_MTB{
	meta:
		description = "Trojan:Win32/Diple.GMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 d8 88 07 47 8b 85 90 01 04 83 e8 03 2b f8 97 83 c7 03 88 07 ff 85 90 01 04 ff 8d 90 01 04 0f 85 90 00 } //5
		$a_03_1 = {83 04 24 11 58 bb 90 01 04 31 18 83 c0 04 e2 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}