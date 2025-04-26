
rule Trojan_Win32_Glupteba_RH_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e9 05 c7 05 ?? ?? ?? ?? 84 10 d6 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 4c 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b 4c 24 ?? 33 cb 33 ce 8d 84 24 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}