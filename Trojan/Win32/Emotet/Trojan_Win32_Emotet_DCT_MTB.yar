
rule Trojan_Win32_Emotet_DCT_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 15 ?? ?? ?? ?? 8b 54 24 ?? 8b 44 24 ?? 0f be 04 02 8a d0 8a cb 0a d8 8b 44 24 ?? f6 d1 f6 d2 0a ca 22 cb 88 08 [0-03] 89 44 24 ?? ff 4c 24 ?? 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}