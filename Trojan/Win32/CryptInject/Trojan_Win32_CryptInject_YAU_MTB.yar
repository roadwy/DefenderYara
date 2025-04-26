
rule Trojan_Win32_CryptInject_YAU_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 64 ff 35 00 00 00 00 64 89 25 00 00 00 00 b8 ?? ?? ?? ?? b9 29 00 00 00 80 30 c7 40 49 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}