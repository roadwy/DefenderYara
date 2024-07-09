
rule Trojan_Win32_Snovir_NS_MTB{
	meta:
		description = "Trojan:Win32/Snovir.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {e8 bc 00 00 00 33 db 39 9e ?? ?? ?? ?? 75 13 8d 85 f8 fe ff ff 50 e8 a7 32 ff ff 59 89 86 ?? ?? ?? ?? 39 5e 78 75 32 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}