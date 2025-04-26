
rule Trojan_Win32_Emotet_PKV_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 04 37 03 c1 99 b9 c3 10 00 00 f7 f9 0f b6 04 32 8b 54 24 10 0f be 0c 2a 51 50 e8 ?? ?? ?? ?? 88 45 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}