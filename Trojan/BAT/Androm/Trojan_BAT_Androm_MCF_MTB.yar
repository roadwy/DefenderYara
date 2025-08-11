
rule Trojan_BAT_Androm_MCF_MTB{
	meta:
		description = "Trojan:BAT/Androm.MCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {58 00 53 00 67 00 2b 00 50 00 43 00 7a 00 66 00 65 00 46 00 67 00 3d 00 3d 00 00 19 48 00 68 00 6c 00 6e 00 6f 00 39 00 64 00 51 00 51 00 67 00 38 00 3d 00 00 4b } //1 XSg+PCzfeFg==ᤀHhlno9dQQg8=䬀
	condition:
		((#a_01_0  & 1)*1) >=1
 
}