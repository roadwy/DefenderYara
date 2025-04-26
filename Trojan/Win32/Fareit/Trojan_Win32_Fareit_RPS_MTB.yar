
rule Trojan_Win32_Fareit_RPS_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 07 4e 75 e3 c7 07 01 00 00 00 90 90 89 f6 ff 07 81 3f ?? ?? ?? ?? 75 f3 6a 04 68 00 30 00 00 68 d3 b5 00 00 6a 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}