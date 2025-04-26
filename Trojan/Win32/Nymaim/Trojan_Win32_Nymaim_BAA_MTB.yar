
rule Trojan_Win32_Nymaim_BAA_MTB{
	meta:
		description = "Trojan:Win32/Nymaim.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {5b 23 1f 8d 7f 04 83 eb 2f c1 cb 08 29 cb 4b 53 59 c1 c1 09 d1 c9 89 1a 8d 52 04 83 ee fc 81 fe 88 06 00 00 75 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}