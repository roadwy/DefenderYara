
rule Trojan_Win64_IcedID_TRE_MTB{
	meta:
		description = "Trojan:Win64/IcedID.TRE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff c1 c1 ea 08 0f af c1 49 63 49 68 41 89 81 ?? ?? ?? ?? 49 8b 81 a8 00 00 00 88 14 01 41 ff 41 68 49 63 49 68 48 8b 05 b1 73 05 00 44 88 04 01 b8 01 00 00 00 41 2b 81 ?? ?? ?? ?? 41 ff 41 68 2b 05 07 73 05 00 48 8b 0d d8 72 05 00 01 41 34 41 8b 81 c4 00 00 00 35 a8 a5 f3 00 29 05 53 73 05 00 49 81 fe 00 27 02 00 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}