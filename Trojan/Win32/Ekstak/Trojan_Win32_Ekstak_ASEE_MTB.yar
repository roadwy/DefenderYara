
rule Trojan_Win32_Ekstak_ASEE_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 ec bc 00 00 00 8d 44 24 00 56 57 50 ff 15 ?? ?? 4c 00 8d 4c 24 18 51 ff 15 ?? ?? 4c 00 8b 54 24 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}