
rule Trojan_Win32_Amadey_GHG_MTB{
	meta:
		description = "Trojan:Win32/Amadey.GHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 33 32 0e 8b 57 10 8b 5f 14 88 4d fc 3b d3 73 90 01 01 8d 42 01 89 47 10 8b c7 83 fb 10 72 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}