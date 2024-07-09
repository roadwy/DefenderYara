
rule Trojan_Win32_Farfli_CZ_MTB{
	meta:
		description = "Trojan:Win32/Farfli.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 55 fc 81 e2 ?? ?? ?? ?? 8b 45 08 03 45 e0 8a 08 32 4c 55 ec 8b 55 08 03 55 e0 88 0a 66 8b 45 fc 66 05 01 00 66 89 45 fc eb } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}