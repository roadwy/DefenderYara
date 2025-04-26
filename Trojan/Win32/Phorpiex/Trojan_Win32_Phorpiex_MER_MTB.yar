
rule Trojan_Win32_Phorpiex_MER_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.MER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 fc 8d 3c 03 e8 ?? ?? ?? ?? 30 07 83 6d ?? 01 39 75 ?? 7d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}