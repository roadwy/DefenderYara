
rule Trojan_Win32_BadJoke_ABD_MTB{
	meta:
		description = "Trojan:Win32/BadJoke.ABD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d0 83 ec 04 c7 44 24 04 00 00 00 00 c7 04 24 02 ?? ?? ?? ?? ?? ?? ?? ?? 83 ec 08 89 45 f4 c7 44 24 08 2c 02 00 00 c7 44 24 04 00 00 00 00 8d 85 c8 fd ff ff 89 04 24 e8 ?? ?? ?? ?? c7 85 c8 fd ff ff 2c 02 00 00 8d 85 c8 fd ff ff 89 44 24 04 8b 45 f4 89 04 24 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}