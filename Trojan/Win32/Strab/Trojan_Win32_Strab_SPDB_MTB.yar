
rule Trojan_Win32_Strab_SPDB_MTB{
	meta:
		description = "Trojan:Win32/Strab.SPDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {69 d2 fd 43 03 00 81 c2 c3 9e 26 00 89 15 ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 30 0c 30 83 ff 0f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}