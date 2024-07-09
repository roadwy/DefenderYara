
rule Trojan_Win32_Zenpak_AMBB_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AMBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 0c 32 8b 55 ?? 88 0c 32 8b 4d ?? 39 cf 89 7d } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}