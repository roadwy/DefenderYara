
rule Trojan_Win32_Zusy_AMBE_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {c0 c8 03 32 83 ?? ?? ?? ?? 6a 0d 88 81 ?? ?? ?? ?? 8d 43 01 99 5b f7 fb 41 8b da 3b ce 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}