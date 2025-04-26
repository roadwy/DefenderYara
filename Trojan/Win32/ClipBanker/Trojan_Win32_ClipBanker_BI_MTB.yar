
rule Trojan_Win32_ClipBanker_BI_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {85 c0 0f 84 86 00 00 00 ff 75 08 ff 15 c0 41 ?? ?? 85 c0 74 79 83 65 e8 00 33 c0 c7 45 ec 07 00 00 00 66 89 45 d8 21 45 fc 8d 45 d8 50 e8 70 00 00 00 3c 01 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}