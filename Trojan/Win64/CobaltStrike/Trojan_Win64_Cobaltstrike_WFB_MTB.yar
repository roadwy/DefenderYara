
rule Trojan_Win64_Cobaltstrike_WFB_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.WFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 30 46 fe 41 8b 44 8d 08 41 31 44 95 08 41 8b 44 ad 08 41 8d 0c 00 43 31 4c 95 08 49 ff cf } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}