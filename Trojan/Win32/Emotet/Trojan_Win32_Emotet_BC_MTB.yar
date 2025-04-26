
rule Trojan_Win32_Emotet_BC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 32 0f b6 04 08 03 c2 99 f7 fb 8b 45 ?? 03 d7 03 55 ?? 8a 14 02 8b 45 ?? 30 10 ff 45 ?? 8b 45 ?? 3b 45 ?? 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}