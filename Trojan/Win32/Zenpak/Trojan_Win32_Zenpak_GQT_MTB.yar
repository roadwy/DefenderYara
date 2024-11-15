
rule Trojan_Win32_Zenpak_GQT_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GQT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c2 31 c2 89 d0 83 c2 ?? 8d 05 ?? ?? ?? ?? 31 20 01 c2 4a 48 29 d0 e8 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}