
rule Trojan_Win32_Dejandet_F_MTB{
	meta:
		description = "Trojan:Win32/Dejandet.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {64 a1 30 00 00 00 8b 40 68 c1 e8 08 a8 01 75 90 01 01 ff 75 08 ff 15 1c f0 40 00 50 ff 15 20 f0 40 00 ff 75 08 e8 4f 00 00 00 59 ff 75 08 ff 15 04 f0 40 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}