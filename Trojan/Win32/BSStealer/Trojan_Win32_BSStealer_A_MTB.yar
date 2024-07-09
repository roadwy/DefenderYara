
rule Trojan_Win32_BSStealer_A_MTB{
	meta:
		description = "Trojan:Win32/BSStealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be c0 33 c3 69 d8 ?? ?? ?? ?? 8a 01 41 84 c0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}