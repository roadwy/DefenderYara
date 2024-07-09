
rule Trojan_Win32_Emotet_DHK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 ca 8d 14 30 33 ca 2b f9 e8 ?? ?? ?? ?? 4d 75 ?? 8b 44 24 1c 89 38 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}