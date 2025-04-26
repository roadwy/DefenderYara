
rule Trojan_Win32_GuLoader_SIBF_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SIBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 f9 00 0f 85 ?? ?? ?? ?? [0-20] 8b 1c 0e [0-20] 89 1c 08 [0-20] bb ?? ?? ?? ?? [0-20] c7 45 ?? ?? ?? ?? ?? [0-20] 90 18 c7 45 ?? ?? ?? ?? ?? [0-20] 50 [0-20] 5a [0-20] 03 55 90 1b 06 [0-20] 8b 3a [0-20] 90 18 31 df [0-20] c7 02 ?? ?? ?? ?? [0-20] 01 3a [0-20] ff 45 90 1b 06 [0-20] ff 45 90 1b 06 [0-20] ff 45 90 1b 06 [0-20] 90 18 [0-20] ff 45 90 1b 06 [0-20] 8b 7d 90 1b 06 [0-20] 3b 7d 90 1b 0a 0f 85 ?? ?? ?? ?? [0-20] ff d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}