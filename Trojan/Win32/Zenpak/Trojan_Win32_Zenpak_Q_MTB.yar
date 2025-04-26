
rule Trojan_Win32_Zenpak_Q_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.Q!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 d0 48 29 d0 01 25 ?? ?? ?? ?? 4a 31 c2 89 c2 4a b9 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}