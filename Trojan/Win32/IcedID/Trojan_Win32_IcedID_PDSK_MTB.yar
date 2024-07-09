
rule Trojan_Win32_IcedID_PDSK_MTB{
	meta:
		description = "Trojan:Win32/IcedID.PDSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 54 24 10 05 20 ab 8f 01 89 02 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? c1 e0 05 bd } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}