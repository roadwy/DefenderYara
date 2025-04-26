
rule Trojan_Win32_Razy_XA_MTB{
	meta:
		description = "Trojan:Win32/Razy.XA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 08 81 ea ?? ?? ?? ?? 09 ff 81 c0 ?? ?? ?? ?? 81 ef ?? ?? ?? ?? 01 d6 39 d8 75 df 83 ec 04 89 34 24 5a } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}