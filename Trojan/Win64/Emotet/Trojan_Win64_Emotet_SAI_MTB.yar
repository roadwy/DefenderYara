
rule Trojan_Win64_Emotet_SAI_MTB{
	meta:
		description = "Trojan:Win64/Emotet.SAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 d8 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 01 f7 6b ff ?? 29 fb 48 ?? ?? 8a 1c 0b 32 1c 02 48 ?? ?? ?? ?? ?? ?? 88 1c 02 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? 77 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}