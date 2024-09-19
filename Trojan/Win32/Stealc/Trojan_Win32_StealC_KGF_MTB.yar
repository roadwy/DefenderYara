
rule Trojan_Win32_StealC_KGF_MTB{
	meta:
		description = "Trojan:Win32/StealC.KGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 83 c0 64 89 45 fc 83 6d fc ?? 8b 45 08 8a 4d fc 03 c2 30 08 42 3b 55 0c 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}