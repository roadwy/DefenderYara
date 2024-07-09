
rule Trojan_Win32_Zenpak_NA_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 cd 8b 55 e8 88 2c 1a 81 c3 ?? ?? ?? ?? 8b 55 f0 39 d3 89 5d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}