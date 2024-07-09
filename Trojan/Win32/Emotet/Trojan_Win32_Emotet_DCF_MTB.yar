
rule Trojan_Win32_Emotet_DCF_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c2 99 f7 fb [0-10] ff 15 ?? ?? ?? ?? 8a 44 24 ?? 8a c8 8a d3 0a d8 8b 44 24 ?? f6 d2 f6 d1 0a d1 22 d3 88 10 [0-0c] 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}