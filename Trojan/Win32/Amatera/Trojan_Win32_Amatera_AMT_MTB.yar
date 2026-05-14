
rule Trojan_Win32_Amatera_AMT_MTB{
	meta:
		description = "Trojan:Win32/Amatera.AMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 8d 4d db e8 ?? ?? ?? ?? 89 45 d4 83 7d d4 00 75 16 68 d0 07 00 00 ff 15 ?? ?? ?? ?? 8b 4d fc 83 c1 01 89 4d fc } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}