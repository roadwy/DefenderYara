
rule Trojan_Win32_IcedId_PAB_MTB{
	meta:
		description = "Trojan:Win32/IcedId.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 50 8b 15 ?? ?? ?? ?? 2b d1 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 05 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}