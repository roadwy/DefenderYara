
rule Trojan_Win32_AsukaStealer_GVA_MTB{
	meta:
		description = "Trojan:Win32/AsukaStealer.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 75 30 8a 14 0a 8d 8d 48 ff ff ff 32 14 3e e8 f6 81 00 00 47 3b 7d 18 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}