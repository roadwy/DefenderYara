
rule Trojan_Win32_Rozena_MBYF_MTB{
	meta:
		description = "Trojan:Win32/Rozena.MBYF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cf 2b f7 ba ?? ?? ?? ?? 8a 04 0e ?? ?? 8d 49 01 32 c3 ?? ?? 88 41 ff 83 ea 01 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}