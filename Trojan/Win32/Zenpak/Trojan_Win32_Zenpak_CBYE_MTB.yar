
rule Trojan_Win32_Zenpak_CBYE_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.CBYE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {e2 2c 40 31 35 ?? ?? ?? ?? 83 c2 04 83 e8 03 31 d0 4a 89 e8 50 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}