
rule Trojan_Win32_Chapak_EAAL_MTB{
	meta:
		description = "Trojan:Win32/Chapak.EAAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 8c 31 f5 d0 00 00 8b 15 ?? ?? ?? ?? 88 0c 32 46 3b f0 72 } //1
		$a_02_1 = {8b 45 08 8d 0c 07 e8 ?? ?? ?? ?? 30 01 47 3b fb 7c } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}