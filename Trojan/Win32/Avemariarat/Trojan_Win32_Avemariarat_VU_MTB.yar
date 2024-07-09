
rule Trojan_Win32_Avemariarat_VU_MTB{
	meta:
		description = "Trojan:Win32/Avemariarat.VU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 99 f7 bd ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8b 55 ?? 03 55 ?? 0f be 02 8b 8d ?? ?? ?? ?? 0f be 54 0d ?? 33 c2 8b 4d ?? 03 4d ?? 88 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}