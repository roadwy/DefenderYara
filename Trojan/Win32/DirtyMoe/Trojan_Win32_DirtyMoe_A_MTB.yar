
rule Trojan_Win32_DirtyMoe_A_MTB{
	meta:
		description = "Trojan:Win32/DirtyMoe.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 01 99 b9 ?? ?? ?? ?? f7 f9 81 c2 ?? ?? ?? ?? 8b 45 ?? 03 45 ?? 8a 08 32 ca 8b 55 ?? 03 55 ?? 88 0a 8b 45 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}