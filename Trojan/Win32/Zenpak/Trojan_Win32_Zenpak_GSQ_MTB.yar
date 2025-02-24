
rule Trojan_Win32_Zenpak_GSQ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GSQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 28 40 8d 05 ?? ?? ?? ?? 89 38 01 c2 42 83 e8 ?? 31 1d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}