
rule Trojan_Win32_IcedId_DE_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 99 f7 ff 8a 82 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 3b ce 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}