
rule Trojan_Win32_Stealc_EAB_MTB{
	meta:
		description = "Trojan:Win32/Stealc.EAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c3 c1 e8 05 89 45 fc 8b 45 e8 01 45 fc 8b f3 c1 e6 04 03 75 ec 8d 0c 1f 33 f1 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}