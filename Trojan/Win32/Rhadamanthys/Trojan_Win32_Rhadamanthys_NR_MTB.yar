
rule Trojan_Win32_Rhadamanthys_NR_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 33 d2 89 10 e8 9d 13 fb ff e8 ec 13 fb ff 83 7e 90 01 02 75 1d 8b c3 8b 15 3c 85 44 90 00 } //5
		$a_03_1 = {53 a1 0c 42 46 00 83 38 00 74 0a 8b 1d 90 01 04 8b 1b ff d3 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}