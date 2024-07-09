
rule Trojan_Win32_Plite_A_MTB{
	meta:
		description = "Trojan:Win32/Plite.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 14 0c 66 85 d7 8d ad ?? ?? ?? ?? f8 80 d1 ?? 8b 4c 25 ?? f5 f8 3b e3 33 cb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}