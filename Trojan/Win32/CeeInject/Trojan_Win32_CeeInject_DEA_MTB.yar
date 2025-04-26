
rule Trojan_Win32_CeeInject_DEA_MTB{
	meta:
		description = "Trojan:Win32/CeeInject.DEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {69 c0 bb 1e 00 00 99 b9 bb 1e 00 00 f7 f9 33 d2 8a 94 05 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 25 ff 00 00 00 33 d0 8b 4d fc 88 94 0d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}