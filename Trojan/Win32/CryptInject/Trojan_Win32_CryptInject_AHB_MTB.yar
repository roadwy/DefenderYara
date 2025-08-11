
rule Trojan_Win32_CryptInject_AHB_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {39 d2 74 01 ea 31 07 68 ?? ?? ?? ?? 8b 1c 24 83 c4 04 81 c7 04 00 00 00 49 39 d7 75 e3 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}