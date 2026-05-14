
rule Trojan_Win32_Amatera_GVM_MTB{
	meta:
		description = "Trojan:Win32/Amatera.GVM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 f6 0f b6 92 ?? ?? ?? ?? 33 ca 8b 45 f8 03 45 fc 88 08 eb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}