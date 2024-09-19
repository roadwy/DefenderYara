
rule Trojan_Win32_FatalRAT_D_MTB{
	meta:
		description = "Trojan:Win32/FatalRAT.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 85 c0 ?? ?? 8d 34 ?? ?? ?? ?? ?? 66 8b 3e 66 3b 3c 53 ?? ?? 42 83 c6 02 3b d0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}